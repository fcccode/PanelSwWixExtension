del test.pvk
del test.cer
del test.pfx
makecert.exe -n "CN=Pane-SW" "test.cer" /sv "test.pvk" /len 2048 /r
Pvk2Pfx.exe /spc "test.cer" /pfx "test.pfx" /po "123456" /pi "123456" /f /pvk test.pvk
"C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Bin\signtool.exe" sign /f "test.pfx" /p "123456" /t "http://timestamp.comodoca.com/authenticode" /v "bin\Debug\EmbeddedTagUT.msi"

