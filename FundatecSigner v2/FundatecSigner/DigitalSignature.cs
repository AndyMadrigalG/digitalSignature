using FundatecSigner;

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Permissions;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.log;
using iTextSharp.text.pdf.security;


using Renci.SshNet;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;
using System.Net;


namespace FundatecSigner{
    public class DigitalSignature
    {
        string myFilePath;
        string arguFile;
        string savePath;
        string fontPath = Application.StartupPath + @"\GOTHIC.ttf";
        string imagePath = Application.StartupPath + @"\selloLargo.png";
        string motivo;
        string modulo;
        int cantFirmas;
        X509Certificate2 cert;

        public DigitalSignature(string pMyFilePath, string pSavePath, string pMotivo, string pModulo,string pCedula,string pArguFile)
        {
            this.myFilePath = pMyFilePath;
            this.savePath = pSavePath;
            this.motivo = pMotivo;
            this.modulo = pModulo;
            this.cert = loadCertificate(pCedula);
            this.arguFile = pArguFile;
            this.cantFirmas = numFirmas();
            if (this.cantFirmas >= 14)
            {
                MessageBox.Show("No se pude firmar el archivo. La hoja de firmas está llena", "Firma Digital Fundatec", MessageBoxButtons.OK, MessageBoxIcon.Information, MessageBoxDefaultButton.Button1);
                salir(this.myFilePath, null, this.arguFile);
            }
            preFirma();
        }

        public DigitalSignature(){}

        public void preFirma()
        {
            IList<X509Certificate> chain = new List<X509Certificate>();
            X509Certificate2 pk = this.cert;
            X509Chain x509chain = new X509Chain();
                x509chain.Build(pk);

                foreach (X509ChainElement x509ChainElement in x509chain.ChainElements)
                {
                    chain.Add(DotNetUtilities.FromX509Certificate(x509ChainElement.Certificate));
                }

            //ser revisa si el certificado contiene la direccion web del servidor de estampado de tiempo.
            IOcspClient ocspClient = new OcspClientBouncyCastle();
            ITSAClient tsaClient = null;
            for (int i = 0; i < chain.Count; i++)
            {
                X509Certificate cert = chain[i];
                String tsaUrl = CertificateUtil.GetTSAURL(cert);
                if (tsaUrl != null)
                {
                    tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    break;
                }
            }
            if (tsaClient == null)
            {
                if (AccesoInternet() == true)
                {
                    tsaClient = new TSAClientBouncyCastle("http://tsa.sinpe.fi.cr/tsahttp/");
                }
            }
            IList<ICrlClient> crlList = new List<ICrlClient>();
            crlList.Add(new CrlClientOnline(chain));
            
            Sign(this.myFilePath, this.savePath, chain, pk, DigestAlgorithms.SHA256, CryptoStandard.CMS, this.motivo , crlList, ocspClient, tsaClient, 0,this.imagePath);
        }

        public void Sign(String src, String dest,ICollection<X509Certificate> chain, X509Certificate2 pk,String digestAlgorithm, CryptoStandard subfilter,String reason,ICollection<ICrlClient> crlList,IOcspClient ocspClient,ITSAClient tsaClient,int estimatedSize, string PathImagenApareceFirma)
        {   
            // Creating the reader and the stamper
            PdfReader reader = null;
            PdfStamper stamper = null;
            FileStream os = null;
            try
            {
                reader = new PdfReader(src);
                os = new FileStream(dest, FileMode.OpenOrCreate);
                //se agregar los parametros especialmente true para que el archivo permita otras firmas.
                stamper = PdfStamper.CreateSignature(reader, os, '\0', Path.GetTempFileName(), true);
                
                // Creating the appearance 
                PdfSignatureAppearance signatureApearance = stamper.SignatureAppearance;
                signatureApearance.Reason = reason;

                //Donde va a ir la firma exactamente
                int numberofPages = reader.NumberOfPages;//en la ultima página
                int x1 = 40, y1 = 640 - (this.cantFirmas % 7 * 90), x2 = 290, y2 = 730 - (this.cantFirmas % 7 * 90); // (x1 [50,490](2)), (y2 [680,50](7) )
                
                if (this.cantFirmas >= 7)//se ha llenado la pagina de firmas, usa la segunda columna
                {
                    x1 += 280;
                    x2 += 280;
                }
                
                //Personal Font
                BaseFont customfont = BaseFont.CreateFont(this.fontPath, BaseFont.CP1252, BaseFont.EMBEDDED);
                Font personalFont = new Font(customfont, 10, iTextSharp.text.Font.NORMAL);
                signatureApearance.Layer2Font = personalFont;
                 
                //Personal Image
                System.Drawing.Image background = System.Drawing.Image.FromFile(this.imagePath);
                iTextSharp.text.Image watermark = iTextSharp.text.Image.GetInstance(background, System.Drawing.Imaging.ImageFormat.Png);
                signatureApearance.Image = watermark;
                signatureApearance.Image.SetAbsolutePosition(0, 0);

                string[] subjectAttributes = this.cert.Subject.Split(',');
                char[] delimiters = new char[] { '=', '(', ' ' };
                string[] nombre = subjectAttributes[0].Split(delimiters, StringSplitOptions.RemoveEmptyEntries);

                string nombreCompleto = "";
                for (int i = 1; i < nombre.Length - 1; i++)
                {
                    string palabra = nombre[i];
                    for (int j = 0; j < palabra.Length; j++)
                    {
                        string letra = palabra[j].ToString();
                        if (j == 0)
                        {//primera letra
                            if (i == 1)
                            {//primetra palabra
                                nombreCompleto += letra.ToUpper();
                            }
                            else
                            {
                                nombreCompleto += (" " + letra.ToUpper());
                            }
                        }
                        else
                        {//resto de la palabra
                            nombreCompleto += letra.ToLower();
                        }
                    }
                }

                signatureApearance.Layer2Text = "Firmado Digitalmente por:\n" + nombreCompleto + "\nCédula: " + getCedula(this.cert) + "\n \nFecha: " + signatureApearance.SignDate;
                signatureApearance.SetVisibleSignature(new iTextSharp.text.Rectangle(x1, y1, x2, y2), numberofPages, null);//(415, 100, 585, 40)
                
                // Creating the signature
                IExternalSignature pks = new X509Certificate2Signature(pk, digestAlgorithm);
                MakeSignature.SignDetached(signatureApearance, pks, chain, crlList, ocspClient, tsaClient, estimatedSize,subfilter);
            }
            finally
            {
                if (reader != null)
                    reader.Close();
                if (stamper != null)
                    stamper.Close();
                if (os != null)
                    os.Close();
            }
        }

        public bool AccesoInternet()
        {
            try
            {
                System.Net.IPHostEntry host = System.Net.Dns.GetHostEntry("www.google.com");
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public X509Certificate2 loadCertificate(string cedula)
        {
            var myPersonalStore = new X509Store(); //Get certificate - Open the currently logged-in user certificate store //StoreName.My, StoreLocation.CurrentUser
            myPersonalStore.Open(OpenFlags.ReadOnly); //open the store only for reading certificates
            //encontrar por cedula
            X509Certificate2 resul = null;
            foreach (X509Certificate2 certi in myPersonalStore.Certificates)
            {
                try
                {
                    string ced = getCedula(certi);
                    if (getCedula(certi).Equals(cedula))
                    {
                        //encontó el cert
                        resul = certi;
                        break;
                    }
                }
                catch (Exception) {/*si no es un certificado valido, no haga nada*/}
            }
            //terminó la busqueda
            if (resul != null)
            {
                myPersonalStore.Close();
                return resul;
            }
            else
            {
                //llama una ventana
                DialogResult response = MessageBox.Show("Su certificado Público no ha sido encontrado, por favor asegúrese que:\n    >Tiene los drivers de firma instalados\n    >La tarjeta está bien conectada\n    >La tarjeta sea de su propiedad", "Firma Digital Fundatec", MessageBoxButtons.RetryCancel, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1);
                if (response == DialogResult.Retry)
                {
                    loadCertificate(cedula);
                }
                else if ((response == DialogResult.Cancel) || (response == DialogResult.Abort))
                {
                    Environment.Exit(0);
                }
                return resul; //nunca debería llegar aquí
            }
        }

        private string getCedula(X509Certificate2 pCertificate)
        {
            string[] subjectAttributes = pCertificate.Subject.Split(',');
            char[] delimiters = new char[] { '=', '(', ' ' };
            string[] nombre = subjectAttributes[0].Split(delimiters, StringSplitOptions.RemoveEmptyEntries);
            string[] ced = subjectAttributes[6].Split('=');
            string cedula = ced[1];
            string[] resul = cedula.Split('-');
            return resul[1] + "-" + resul[2] + "-" + resul[3];
        }

        private int numFirmas()
        {
            byte[] pdfData = File.ReadAllBytes(this.myFilePath);
            var reader = new PdfReader(pdfData);
            AcroFields fields = reader.AcroFields;
            var nombres = fields.GetSignatureNames();
            int cantFirmas = nombres.Count;
            return cantFirmas;
        }

        public void bajar(string downloadPath, string fileName, string sftpURL)
        {
            string[] info = sftpURL.Split('/');
            string sftpDirectory = "";
            foreach (string folder in info)
            {
                if (!folder.Equals(info[0]))
                {
                    sftpDirectory += ("/" + folder);
                }
            }
            String Host = info[0];
            int Port = 22;
            String Username = "root";
            String Password = "A@4Ps5d4tN";

            var client = new SftpClient(Host, Port, Username, Password);
            client.Connect();
            if (!client.IsConnected)
            {
                MessageBox.Show("Client is not connected");
            }

            var fileStream = new FileStream(downloadPath, FileMode.OpenOrCreate);
            if (fileStream == null)
            {
                MessageBox.Show("FileStream is NULL");
            }

            client.BufferSize = 4 * 1024;
            client.DownloadFile(".." + sftpDirectory + fileName, fileStream, null);
            fileStream.Close();
            client.Disconnect();
            client.Dispose();
        }

        public void subir(string savePath, string fileName, string sftpURL)
        {
            string[] info = sftpURL.Split('/');
            string sftpDirectory = "";
            foreach (string folder in info)
            {
                if (!folder.Equals(info[0]))
                {
                    sftpDirectory += ("/" + folder);
                }
            }
            String Host = info[0];
            int Port = 22;
            String Username = "root";
            String Password = "A@4Ps5d4tN";

            var client = new SftpClient(Host, Port, Username, Password);
            client.Connect();
            if (!client.IsConnected)
            {
                MessageBox.Show("Client is not connected");
            }

            var fileStream = new FileStream(savePath, FileMode.OpenOrCreate);
            if (fileStream == null)
            {
                MessageBox.Show("FileStream is NULL");
            }

            client.BufferSize = 4 * 1024;
            client.UploadFile(fileStream, ".." + sftpDirectory + fileName, null);
            fileStream.Close();
            client.Disconnect();
            client.Dispose();
        }

        public void mostrarError(string message, Exception e)
        {
            DialogResult response = MessageBox.Show(message + e.Message + "\n \nDesea mas detalles del error?", "Fundatec Signer", MessageBoxButtons.YesNo, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1);
            if (response == DialogResult.Yes)
            {
                MessageBox.Show("El error ha ocurrido en:\n" + e.StackTrace.ToLower(), "Fundatec Signer", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1);
                return;
            }
            else if ((response == DialogResult.No) || (response == DialogResult.Abort))
            {
                return;
            }
        }

        public void salir(string down = null, string up = null, string arg = null)
        {
            if (down != null)
            {
                System.IO.File.Delete(down); //elimina el archivo descargado                                               
            }
            if (up != null)
            {
                System.IO.File.Delete(up); //elimina el archivo a subir                                              
            }
            if (arg != null)
            {
                System.IO.File.Delete(arg); //elimina el ejecutable de firma                                             
            }
            Environment.Exit(0);
        }
    }
}
