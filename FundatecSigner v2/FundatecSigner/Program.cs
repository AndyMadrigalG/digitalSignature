
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FundatecSigner
{
    class Program
    {
        static void Main(string[] args)
        {   //info = ced|nombreArchivo|urlFTP
                       
            if (args.Length == 0)
            {
                MessageBox.Show("Esta aplicación funciona únicamente al abrir archivos .fundatec descargados de nuestra página.", "Firma Digital Fundatec", MessageBoxButtons.OK, MessageBoxIcon.Information, MessageBoxDefaultButton.Button1);
                Environment.Exit(0);
            }

            string[] info = System.IO.File.ReadAllText(System.IO.Path.GetFullPath(args[0])).Split('|');
            string cedula = info[0].Trim(); // en formato 02-0654-0118
            string fileName = info[1].Trim(); // nombre del archivo
            string sftpURL = info[2].Trim(); //url de carga y descarga sftp
            string modulo = info[3].Trim(); //modulo que pide la firma
            
            string savePath = Application.StartupPath + @"\UploadFiles\" + fileName;
            string downloadPath =Application.StartupPath + @"\DownloadFiles\" + fileName;
            DigitalSignature ds = new DigitalSignature();

            //BAJAR
            try
            {
                ds.bajar(downloadPath, fileName, sftpURL);
            }
            catch (Exception e)
            {
                ds.mostrarError("Error al descargar el archivo: ", e);
                ds.salir(downloadPath);
            }
            //FIRMAR
            try
            {
                DigitalSignature fs = new DigitalSignature(downloadPath, savePath, "Firma FUNDATEC", modulo, cedula, args[0]);//02-0654-0118 //03-0275-0576
            }
            catch (Exception e)
            {
                ds.mostrarError("Error en el proceso: ", e);
                ds.salir(downloadPath, savePath);
            }
            //SUBIR
            try
            {
                //subir el archivo guardado en savePath a ftpURL via ftp con sus respectivos credenciales
                ds.subir(savePath, fileName, sftpURL);
                MessageBox.Show("El documento fué firmado con exito", "Firma Digital Fundatec", MessageBoxButtons.OK, MessageBoxIcon.Information, MessageBoxDefaultButton.Button1);
                ds.salir(downloadPath, savePath, args[0]);
            }
            catch (Exception e)
            {
                ds.mostrarError("Error al subir el archivo: ", e);
                ds.salir(downloadPath, savePath);
            }
        }
    }//end class
}
