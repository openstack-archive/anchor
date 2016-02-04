' Generate the CMC request with a hardcoded CN from the current user context

Const ContextUser = 1
const XCN_CERT_X500_NAME_STR = 3

Set fso = CreateObject ("Scripting.FileSystemObject")

Set req = CreateObject("X509Enrollment.CX509CertificateRequestCmc")

Set xreq = CreateObject("X509Enrollment.CX509CertificateRequestPkcs10")
xreq.Initialize ContextUser

xreq.Subject = CreateObject( "X509Enrollment.CX500DistinguishedName" )
xreq.Subject.Encode "CN=anchor-test.example.com", XCN_CERT_X500_NAME_STR

req.InitializeFromInnerRequest xreq

req.Encode

outFile="cmc.req"
Set objFile = fso.CreateTextFile(outFile,True)
objFile.WriteLine "-----BEGIN CERTIFICATE REQUEST-----"
objFile.WriteLine req.RawData
objFile.WriteLine "-----END CERTIFICATE REQUEST-----"
objFile.Close

