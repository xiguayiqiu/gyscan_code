package format_conversion

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"

	"github.com/xiguayiqiu/gyscan_code/binary_stream"
)

func convertImage(data []byte, srcFmt, dstFmt FormatType) ([]byte, error) {
	if srcFmt == dstFmt {
		return data, nil
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("format_conversion: decode %s: %w", srcFmt, err)
	}

	switch dstFmt {
	case FormatPNG:
		return encodePNG(img)
	case FormatJPG:
		return encodeJPG(img)
	case FormatBMP:
		return encodeBMP(img)
	case FormatICO:
		return encodeICO(img)
	case FormatWEBP:
		return encodeWEBP(img, srcFmt)
	default:
		return nil, fmt.Errorf("format_conversion: unsupported target image format %s", dstFmt)
	}
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("format_conversion: encode PNG: %w", err)
	}
	return buf.Bytes(), nil
}

func encodeJPG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		return nil, fmt.Errorf("format_conversion: encode JPG: %w", err)
	}
	return buf.Bytes(), nil
}

func encodeBMP(img image.Image) ([]byte, error) {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	rowSize := (w*3 + 3) & ^3
	pixelSize := rowSize * h
	fileSize := 54 + pixelSize

	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("BM"))
	s.WriteUint32(uint32(fileSize))
	s.WriteUint16(0)
	s.WriteUint16(0)
	s.WriteUint32(54)

	s.WriteUint32(40)
	s.WriteInt32(int32(w))
	s.WriteInt32(int32(h))
	s.WriteUint16(1)
	s.WriteUint16(24)
	s.WriteUint32(0)
	s.WriteUint32(uint32(pixelSize))
	s.WriteInt32(2835)
	s.WriteInt32(2835)
	s.WriteUint32(0)
	s.WriteUint32(0)

	for y := h - 1; y >= 0; y-- {
		rowStart := s.Len()
		for x := 0; x < w; x++ {
			r, g, b, _ := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			s.WriteByte(byte(b >> 8))
			s.WriteByte(byte(g >> 8))
			s.WriteByte(byte(r >> 8))
		}
		for s.Len()-rowStart < rowSize {
			s.WriteByte(0)
		}
	}

	return s.Bytes(), nil
}

func encodeICO(img image.Image) ([]byte, error) {
	sizes := []int{256, 128, 64, 48, 32, 16}
	var images []image.Image

	for _, size := range sizes {
		b := img.Bounds()
		if b.Dx() >= size && b.Dy() >= size {
			images = append(images, resizeImage(img, size, size))
		}
	}
	if len(images) == 0 {
		images = append(images, resizeImage(img, 32, 32))
	}

	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteUint16(0)
	s.WriteUint16(1)
	s.WriteUint16(uint16(len(images)))

	type entry struct {
		w, h  uint8
		size  uint32
		off   uint32
		data  []byte
	}
	var entries []entry

	dataOffset := uint32(6 + 16*len(images))
	for _, im := range images {
		pngData, _ := encodePNG(im)
		b := im.Bounds()
		w := b.Dx()
		h := b.Dy()
		if w >= 256 {
			w = 0
		}
		if h >= 256 {
			h = 0
		}

		entries = append(entries, entry{
			w:    uint8(w),
			h:    uint8(h),
			size: uint32(len(pngData)),
			off:  dataOffset,
			data: pngData,
		})
		dataOffset += uint32(len(pngData))
	}

	for _, e := range entries {
		s.WriteByte(e.w)
		s.WriteByte(e.h)
		s.WriteByte(0)
		s.WriteByte(0)
		s.WriteUint16(1)
		s.WriteUint16(32)
		s.WriteUint32(e.size)
		s.WriteUint32(e.off)
	}

	for _, e := range entries {
		s.WriteBytes(e.data)
	}

	return s.Bytes(), nil
}

func encodeWEBP(img image.Image, srcFmt FormatType) ([]byte, error) {
	var imageData []byte
	if srcFmt == FormatPNG {
		imageData, _ = encodePNG(img)
	} else {
		imageData, _ = encodeJPG(img)
	}

	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("RIFF"))
	fileSizePos := s.Len()
	s.WriteUint32(0)
	s.WriteBytes([]byte("WEBP"))

	s.WriteBytes([]byte("VP8X"))
	s.WriteUint32(10)

	flags := byte(0)
	if !bounds.Empty() {
		_, _, _, a := img.At(bounds.Min.X, bounds.Min.Y).RGBA()
		if a > 0 {
			flags |= 0x10
		}
	}
	s.WriteByte(flags)
	s.WriteBytes([]byte{0, 0, 0})
	writeUint24LE(s, uint32(w-1))
	writeUint24LE(s, uint32(h-1))

	chunkTag := "VP8L"
	if srcFmt == FormatJPG {
		chunkTag = "VP8 "
	}
	s.WriteBytes([]byte(chunkTag))

	chunkSizePos := s.Len()
	s.WriteUint32(uint32(len(imageData)))
	s.WriteBytes(imageData)

	if len(imageData)%2 != 0 {
		s.WriteByte(0)
	}

	fileSize := uint32(s.Len() - 8)
	binary.LittleEndian.PutUint32(s.Bytes()[fileSizePos:fileSizePos+4], fileSize)
	binary.LittleEndian.PutUint32(s.Bytes()[chunkSizePos:chunkSizePos+4], uint32(len(imageData)))

	return s.Bytes(), nil
}

func writeUint24LE(s *binary_stream.Stream, v uint32) {
	s.WriteByte(byte(v & 0xFF))
	s.WriteByte(byte((v >> 8) & 0xFF))
	s.WriteByte(byte((v >> 16) & 0xFF))
}

func encodeBMPSimple(w, h int, pixels []byte) []byte {
	rowSize := (w*3 + 3) & ^3
	pixelSize := rowSize * h
	fileSize := 54 + pixelSize

	s := binary_stream.NewWithOrder(binary.LittleEndian)

	s.WriteBytes([]byte("BM"))
	s.WriteUint32(uint32(fileSize))
	s.WriteUint16(0)
	s.WriteUint16(0)
	s.WriteUint32(54)

	s.WriteUint32(40)
	s.WriteInt32(int32(w))
	s.WriteInt32(int32(h))
	s.WriteUint16(1)
	s.WriteUint16(24)
	s.WriteUint32(0)
	s.WriteUint32(uint32(pixelSize))
	s.WriteInt32(2835)
	s.WriteInt32(2835)
	s.WriteUint32(0)
	s.WriteUint32(0)

	for y := h - 1; y >= 0; y-- {
		off := y * w * 3
		rowStart := s.Len()
		for x := 0; x < w; x++ {
			s.WriteByte(pixels[off+x*3+2])
			s.WriteByte(pixels[off+x*3+1])
			s.WriteByte(pixels[off+x*3])
		}
		for s.Len()-rowStart < rowSize {
			s.WriteByte(0)
		}
	}
	return s.Bytes()
}

func resizeImage(img image.Image, newW, newH int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, newW, newH))
	b := img.Bounds()
	scaleX := float64(b.Dx()) / float64(newW)
	scaleY := float64(b.Dy()) / float64(newH)

	for y := 0; y < newH; y++ {
		for x := 0; x < newW; x++ {
			srcX := int(float64(x) * scaleX)
			srcY := int(float64(y) * scaleY)
			if srcX >= b.Dx() {
				srcX = b.Dx() - 1
			}
			if srcY >= b.Dy() {
				srcY = b.Dy() - 1
			}
			dst.Set(x, y, img.At(b.Min.X+srcX, b.Min.Y+srcY))
		}
	}
	return dst
}

func imgToRGBA(img image.Image) *image.RGBA {
	if rgba, ok := img.(*image.RGBA); ok {
		return rgba
	}
	b := img.Bounds()
	dst := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			dst.Set(x, y, img.At(x, y))
		}
	}
	return dst
}

func imgToNRGBA(img image.Image) *image.NRGBA {
	if nrgba, ok := img.(*image.NRGBA); ok {
		return nrgba
	}
	b := img.Bounds()
	dst := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(r >> 8),
				G: uint8(g >> 8),
				B: uint8(b >> 8),
				A: uint8(a >> 8),
			})
		}
	}
	return dst
}