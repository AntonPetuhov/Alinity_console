using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Text.RegularExpressions;
using System.Configuration;
using System.Data.SqlClient;

namespace Alinity_console
{
    internal class Program
    {
        #region Settings
        public static string AnalyzerCode = "909";                  // код из аналайзер конфигурейшн, который связывает прибор в PSMV2
        public static string AnalyzerConfigurationCode = "ALINITY"; // код прибора из аналайзер конфигурейшн

        //public static string IPadress = "172.18.95.31"; // cgm-app12, подсетка приборов
        public static string IPadress = "10.128.131.112"; // cgm-app12
        public static int port = 8020;                    // порт, который драйвер слушает tcp сервером

        // порт, используемый прибором для получения сообщений от ЛИС. Драйвер должен подключаться к анализатору по порту 50020 клиентом
        public static int receiving_port = 50020;
        public static string analyzerIPadress = "10.128.143.200"; // ip адрес роутера, WAN

        public static string user = "PSMExchangeUser"; // логин для базы обмена файлами и для базы CGM Analytix
        public static string password = "PSM_123456";  // пароль для базы обмена файлами и для базы CGM Analytix

        public static bool ServiceIsActive;            // флаг для запуска и остановки потока
        public static string AnalyzerResultPath = AppDomain.CurrentDomain.BaseDirectory + "\\AnalyzerResults"; // папка для файлов с результатами

        static object ExchangeLogLocker = new object();    // локер для логов обмена
        static object FileResultLogLocker = new object();  // локер для логов обмена
        static object ServiceLogLocker = new object();     // локер для логов драйвера

        // управляющие биты
        static byte[] VT = { 0x0B }; // <SB>
        static byte[] FS = { 0x1C }; // <EB>
        static byte[] CR = { 0x0D }; // <CR>

        #endregion

        #region функции логов
        // лог обмена с анализатором
        static void ExchangeLog(string Message)
        {
            lock (ExchangeLogLocker)
            {
                string path = AppDomain.CurrentDomain.BaseDirectory + "\\Log\\Exchange";
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                }

                string filename = path + "\\ExchangeThread_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
                if (!System.IO.File.Exists(filename))
                {
                    using (StreamWriter sw = System.IO.File.CreateText(filename))
                    {
                        sw.WriteLine(DateTime.Now + ": " + Message);
                    }
                }
                else
                {
                    using (StreamWriter sw = System.IO.File.AppendText(filename))
                    {
                        sw.WriteLine(DateTime.Now + ": " + Message);
                    }
                }

            }
        }

        // Лог записи результатов в CGM
        static void FileResultLog(string Message)
        {
            try
            {
                lock (FileResultLogLocker)
                {
                    //string path = AppDomain.CurrentDomain.BaseDirectory + "\\Log\\FileResult" + "\\" + DateTime.Now.Year + "\\" + DateTime.Now.Month;
                    string path = AppDomain.CurrentDomain.BaseDirectory + "\\Log\\FileResult";
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }

                    //string filename = path + $"\\{FileName}" + ".txt";
                    string filename = path + $"\\ResultLog_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";

                    if (!System.IO.File.Exists(filename))
                    {
                        using (StreamWriter sw = System.IO.File.CreateText(filename))
                        {
                            sw.WriteLine(DateTime.Now + ": " + Message);
                        }
                    }
                    else
                    {
                        using (StreamWriter sw = System.IO.File.AppendText(filename))
                        {
                            sw.WriteLine(DateTime.Now + ": " + Message);
                        }
                    }
                }
            }
            catch
            {

            }
        }

        // Лог драйвера
        static void ServiceLog(string Message)
        {
            lock (ServiceLogLocker)
            {
                try
                {
                    string path = AppDomain.CurrentDomain.BaseDirectory + "\\Log\\Service";
                    if (!Directory.Exists(path))
                    {
                        Directory.CreateDirectory(path);
                    }

                    string filename = path + "\\ServiceThread_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
                    if (!System.IO.File.Exists(filename))
                    {
                        using (StreamWriter sw = System.IO.File.CreateText(filename))
                        {
                            sw.WriteLine(DateTime.Now + ": " + Message);
                        }
                    }
                    else
                    {
                        using (StreamWriter sw = System.IO.File.AppendText(filename))
                        {
                            sw.WriteLine(DateTime.Now + ": " + Message);
                        }
                    }
                }
                catch
                {

                }
            }
        }
        #endregion

        #region вспомогательные функции
        static byte[] GetByteFromString(string StringPar)
        {
            byte[] FinalArray = { };
            List<string> ManagedBytes = new List<string> { "<STX>", "<ETX>", "<EOT>", "<ENQ>", "<ACK>", "<NAK>", "<SYN>", "<ETB>", "<LF>", "<CR>" };
            Regex regex = new Regex(@"\S*[<](?<Word>\S+)[>]\S*", RegexOptions.RightToLeft, TimeSpan.FromMilliseconds(150));
            Match mat = regex.Match(StringPar);
            if (mat.Success)
            {
                string Res = mat.Result("${Word}");
                string LeftSliceString = StringPar.Substring(0, mat.Groups[1].Index - 1);
                int ValueIndex = mat.Groups[1].Index + Res.Length + 1;
                string RightSliceString = StringPar.Substring(ValueIndex, StringPar.Length - ValueIndex);
                return ConcatByteArray(Encoding.GetEncoding(1251).GetBytes(LeftSliceString), TranslateStrings($"<{Res}>"), GetByteFromString(RightSliceString));
            }
            else
            {
                return Encoding.GetEncoding(1251).GetBytes(StringPar);
            }
        }
        static byte[] TranslateStrings(string StringPar)
        {
            switch (StringPar)
            {
                case "<STX>":
                    byte[] STX = { 0x02 };
                    return STX;
                case "<ETX>":
                    byte[] ETX = { 0x03 };
                    return ETX;
                case "<EOT>":
                    byte[] EOT = { 0x04 };
                    return EOT;
                case "<ENQ>":
                    byte[] ENQ = { 0x05 };
                    return ENQ;
                case "<ACK>":
                    byte[] ACK = { 0x06 };
                    return ACK;
                case "<NAK>":
                    byte[] NAK = { 0x17 };
                    return NAK;
                case "<SYN>":
                    byte[] SYN = { 0x16 };
                    return SYN;
                case "<ETB>":
                    byte[] ETB = { 0x17 };
                    return ETB;
                case "<LF>":
                    byte[] LF = { 0x0A };
                    return LF;
                case "<CR>":
                    byte[] CR = { 0x0D };
                    return CR;
                default:
                    byte[] Def = { 0x0A };
                    return Def;
            }
        }
        static string TranslateBytes(byte BytePar)
        {
            switch (BytePar)
            {
                case 0x02:
                    return "<STX>";
                case 0x03:
                    return "<ETX>";
                case 0x04:
                    return "<EOT>";
                case 0x05:
                    return "<ENQ>";
                case 0x06:
                    return "<ACK>";
                case 0x15:
                    return "<NAK>";
                case 0x16:
                    return "<SYN>";
                case 0x17:
                    return "<ETB>";
                case 0x0A:
                    return "<LF>";
                case 0x0D:
                    return "<CR>";
                default:
                    return "<HZ>";
            }
        }

        //делаем из байт строку с учетом управляющих байт
        public static string GetStringFromBytes(byte[] ReceivedDataPar)
        {
            byte[] BytesForCHecking = { 0x02, 0x03, 0x04, 0x05, 0x06, 0x15, 0x16, 0x17, 0x0D, 0x0A };
            int StepCount = 0;
            bool IsManageByte = false;
            foreach (byte rec_byte in ReceivedDataPar)
            {
                foreach (byte check_byte in BytesForCHecking)
                {
                    if (rec_byte == check_byte)
                    {
                        IsManageByte = true;
                        break;
                    }
                }
                if (IsManageByte) { break; };
                StepCount++;
            }

            if (IsManageByte)
            {
                byte[] SliceByteArray = new byte[ReceivedDataPar.Length - (StepCount + 1)];
                Array.Copy(ReceivedDataPar, StepCount + 1, SliceByteArray, 0, ReceivedDataPar.Length - (StepCount + 1));
                return Encoding.GetEncoding(1251).GetString(ReceivedDataPar, 0, StepCount)
                    + TranslateBytes(ReceivedDataPar[StepCount])
                    + GetStringFromBytes(SliceByteArray);
            }
            else
            {
                return Encoding.GetEncoding(1251).GetString(ReceivedDataPar, 0, ReceivedDataPar.Length);
            }
        }

        //дописываем к номеру месяца ноль если нужно
        public static string CheckZero(int CheckPar)
        {
            string BackPar = "";
            if (CheckPar < 10)
            {
                BackPar = $"0{CheckPar}";
            }
            else
            {
                BackPar = $"{CheckPar}";
            }
            return BackPar;
        }

        //собираем несколько массивов в один
        static Byte[] ConcatByteArray(params Byte[][] ArraysPar)
        {
            // [][] - массив массивов
            Byte[] FinallArray = { };
            for (int i = 0; i < ArraysPar.Length; i++)
            {
                int EndOfGeneralArray = FinallArray.Length;
                Array.Resize(ref FinallArray, FinallArray.Length + ArraysPar[i].Length);
                Array.Copy(ArraysPar[i], 0, FinallArray, EndOfGeneralArray, ArraysPar[i].Length);
            }
            return FinallArray;
        }

        // Создаем файл с результатом, отправленным анализатором
        static void MakeAnalyzerResultFile(string AllMessagePar)
        {
            if (!Directory.Exists(AnalyzerResultPath))
            {
                Directory.CreateDirectory(AnalyzerResultPath);
            }
            DateTime now = DateTime.Now;
            string filename = AnalyzerResultPath + "\\Results_" + now.Year + CheckZero(now.Month) + CheckZero(now.Day) + CheckZero(now.Hour) + CheckZero(now.Minute) + CheckZero(now.Second) + CheckZero(now.Millisecond) + ".res";
            using (System.IO.FileStream fs = new System.IO.FileStream(filename, FileMode.OpenOrCreate))
            {
                foreach (string res in AllMessagePar.Split('\r'))
                {
                    byte[] ResByte = Encoding.GetEncoding(1251).GetBytes(res + "\r\n");
                    fs.Write(ResByte, 0, ResByte.Length);
                }
            }
        }

        // преобразование кода теста в код теста, понятный прибору, для отправки задания
        public static string TranslateToAnalyzerCodes(string CGMTestCodesPar)
        {
            string BackTestCode = "";
            try
            {
                string CGMConnectionString = ConfigurationManager.ConnectionStrings["CGMConnection"].ConnectionString;
                CGMConnectionString = String.Concat(CGMConnectionString, $"User Id = {user}; Password = {password}");
                using (SqlConnection Connection = new SqlConnection(CGMConnectionString))
                {
                    Connection.Open();
                    //ищем код теста в analyzer configuration
                    SqlCommand TestCodeCommand = new SqlCommand(
                       "SELECT TOP 1 k.amt_analyskod FROM konvana k " +
                       $"WHERE k.ins_maskin = '{AnalyzerConfigurationCode}' AND k.met_kod = '{CGMTestCodesPar}' ", Connection);
                    SqlDataReader Reader = TestCodeCommand.ExecuteReader();

                    if (Reader.HasRows) // если есть данные
                    {
                        while (Reader.Read())
                        {
                            if (!Reader.IsDBNull(0)) { BackTestCode = Reader.GetString(0); };
                        }
                    }
                    Reader.Close();
                    Connection.Close();
                }
            }
            catch (Exception error)
            {
                ExchangeLog($"Error: {error}");
            }
            return BackTestCode;
        }

        // Функция преобразования кода теста прибора в код теста PSMV2 в CGM
        public static string TranslateToPSMCodes(string AnalyzerTestCodesPar)
        {
            string BackTestCode = "";
            try
            {
                string CGMConnectionString = ConfigurationManager.ConnectionStrings["CGMConnection"].ConnectionString;
                //string CGMConnectionString = @"Data Source=CGM-APP11\SQLCGMAPP11;Initial Catalog=KDLPROD; Integrated Security=True;";
                CGMConnectionString = String.Concat(CGMConnectionString, $"User Id = {user}; Password = {password}");
                using (SqlConnection Connection = new SqlConnection(CGMConnectionString))
                {
                    Connection.Open();
                    // Ищем только тесты, которые настроены для прибора exias и настроены для PSMV2
                    SqlCommand TestCodeCommand = new SqlCommand(
                       "SELECT k1.amt_analyskod  FROM konvana k " +
                       "LEFT JOIN konvana k1 ON k1.met_kod = k.met_kod AND k1.ins_maskin = 'PSMV2' " +
                       $"WHERE k.ins_maskin = '{AnalyzerConfigurationCode}' AND k.amt_analyskod = '{AnalyzerTestCodesPar}' ", Connection);
                    SqlDataReader Reader = TestCodeCommand.ExecuteReader();

                    if (Reader.HasRows) // если есть данные
                    {
                        while (Reader.Read())
                        {
                            if (!Reader.IsDBNull(0)) { BackTestCode = Reader.GetString(0); };
                        }
                    }
                    Reader.Close();
                    Connection.Close();
                }
            }
            catch (Exception error)
            {
                FileResultLog($"Error: {error}");
            }

            return BackTestCode;
        }

        #endregion

        #region Функции обмена сообщениями с анализатором

        #region отправка прибору теста соединения
        static void NMDNO2Sending(Socket client_, Encoding utf8, string id)
        {
            // ACK^N02 sending
            DateTime now = DateTime.Now;
            string ackDate = now.ToString("yyyyMMddHHmmss");
            // guid ответного сообщения
            Guid guid = Guid.NewGuid();

            // шаблон ответа ACK^N02 в формате HL7 (по мануалу)
            //"MSH|^~\&|LIS|MainLab|Alinity ci|Lab2|20160801021528||ACK^N02^ACK|45bd3540-39d1-4500-b3d5-bd668f752dd3 | P | 2.5.1 |||||| UNICODE UTF - 8"
            string nmdMSH = $@"MSH|^~\&|LisApp|MainFacility|AlinityApp|LabFacility|{ackDate}||NMD^N02^NMD_N02|{guid}|P|2.5.1|||NE|AL||UNICODE UTF-8";
            string nmdNST = $@"NST|N";


            string ackResponse = "";

            ackResponse = nmdMSH + '\r' + nmdNST;

            // строка ответа с результатом
            byte[] SendingMessageBytes;
            //SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), FS, CR);
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), CR, FS, CR);

            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending NMD^N02 to analyzer");
                ExchangeLog("LIS:" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }
        #endregion

        #region отправка подверждения соединения ACK^NO2
        static void ACKNO2Sending(Socket client_, Encoding utf8, string id)
        {
            // ACK^N02 sending
            DateTime now = DateTime.Now;
            string ackDate = now.ToString("yyyyMMddHHmmss");

            // guid ответного сообщения
            Guid guid = Guid.NewGuid();

            // шаблон ответа ACK^N02 в формате HL7 (по мануалу)
            //"MSH|^~\&|LIS|MainLab|Alinity ci|Lab2|20160801021528||ACK^N02^ACK|45bd3540-39d1-4500-b3d5-bd668f752dd3 | P | 2.5.1 |||||| UNICODE UTF - 8"
            string ackMSH = $@"MSH|^~\&|LisApp|MainFacility|AlinityApp|LabFacility|{ackDate}||ACK^N02^ACK|{guid}|P|2.5.1||||||UNICODE UTF-8";
            string ackMSA = $@"MSA|AA|{id}";

            string ackResponse = "";

            ackResponse = ackMSH + '\r' + ackMSA;

            // строка ответа с результатом
            byte[] SendingMessageBytes;
            //SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), FS, CR);
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), CR, FS, CR);

            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending ACK^N02 to analyzer");
                ExchangeLog("LIS:" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }
        #endregion

        #region отправка подверждения на сообщение TCU (прибор отправляет методики, доступные для выполнения) ACK^U10
        static void ACKU10Sending(Socket client_, Encoding utf8, string id)
        {
            // ACK^U10 sending
            DateTime now = DateTime.Now;
            string ackDate = now.ToString("yyyyMMddHHmmss");

            // шаблон ответа ACK^N02 в формате HL7 (по мануалу)
            //"MSH|^~\&|LIS|MainLab|Alinity ci|Lab2|20160801021528||ACK^N02^ACK|45bd3540-39d1-4500-b3d5-bd668f752dd3 | P | 2.5.1 |||||| UNICODE UTF - 8"
            string ackMSH = $@"MSH|^~\&|||||{ackDate}||ACK^U10^ACK|{id}|P|2.5.1||||||UNICODE UTF-8";
            string ackMSA = $@"MSA|AA|{id}";

            string ackResponse = "";

            ackResponse = ackMSH + '\r' + ackMSA;

            // строка ответа с результатом
            byte[] SendingMessageBytes;
            //SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), FS, CR);
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), CR, FS, CR);

            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending ACK^U10 to analyzer");
                ExchangeLog("LIS:" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }
        #endregion

        #region ответ сервера драйвера на запрос задания (подтверждение) RSP^K11 (Query Response)
        // this message is a response message for a Query (RSP^K11^RSP_K11) message
        static void RSPSending(Socket client_, Encoding utf8, string id, string tag, string rid)
        {
            // RSP^K11 sending
            DateTime now = DateTime.Now;
            string rspDate = now.ToString("yyyyMMddHHmmss");
            // guid ответного сообщения
            Guid guid = Guid.NewGuid();

            // шаблон ответа RSP^K11 в формате HL7 (по мануалу)
            string rspMSH = $@"MSH|^~\&|||||{rspDate}||RSP^K11^RSP_K11|{guid}|P|2.5.1||||||UNICODE UTF-8|||LAB-27^IHE";
            string rspMSA = $@"MSA|AA|{id}";
            string rspQAK = $@"QAK|{tag}|OK|WOS^Work Order Step^IHELAW";
            string rspQPD = $@"QPD|WOS^Work Order Step^IHELAW|{tag}|{rid}";

            string rspResponse = rspMSH + '\r' + rspMSA + '\r' + rspQAK + '\r' + rspQPD;

            // строка подтверждения в массив байт
            byte[] SendingMessageBytes;
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(rspResponse), CR, FS, CR);
            // отправляем прибору
            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending response RSP^K11 to analyzer");
                ExchangeLog("LIS (driver as SRV):" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }
        #endregion

        #region отправка прибору задания OML^O33 Order request, ответ клиента драйвера
        static void OMLSending(Socket client_, Encoding utf8, string id, string rid, string pid, string Name, string FName, string birthday, string sex, string sampledate, string testsString, string omlDate)
        {
            // guid ответного сообщения
            Guid guid = Guid.NewGuid();
            // кавычки
            string quot = "\"";

            #region шаблон задания HL7

            string omlMSH = $@"MSH|^~\&|||||{omlDate}||OML^O33^OML_O33|{guid}|P|2.5.1|||NE|AL||UNICODE UTF-8|||LAB-28^IHE";
            string omlPID = $@"PID|1||{pid}||{Name}^{FName}^^^^^L||{birthday}|{sex}";
            string omlPV1 = $@"PV1||N|^NMIC";
            string omlSPM = @"SPM|1|||" + quot + quot + $@"|||||||P^Patient specimen^HL70369||||||{sampledate}"; // sampledate
            string omlSAC = $@"SAC|||{rid}";

            #endregion

            string omlResponse = omlMSH + '\r' + omlPID + '\r' + omlPV1 + '\r' + omlSPM + '\r' + omlSAC + '\r' + testsString;

            // строка c заданием в массив байт
            byte[] SendingMessageBytes;
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(omlResponse), CR, FS, CR);
            // отправляем прибору
            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending Order Request OML^O33 to analyzer");
                ExchangeLog("LIS (driver as CLI):" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }

        }
        #endregion

        #region Формируется блок сообщения OML^O33 с тестами
        public static string OMLCreateTestString(string test, string omlDate)
        {
            // получим test name из Analyzer code (Analyzer configuration)
            char delimiter = '^';
            //string[] analyzer_code = test.Split(delimiter);
            //string test_name = analyzer_code[1];
            string test_name = test.Split('^')[1];
            // шаблон HL7
            string omlORC = $@"ORC|NW||||||||{omlDate}";
            string omlTQ1 = $@"TQ1|||||||||R^^HL70485";
            string omlOBR = $@"OBR||{omlDate}{test_name}||{test}^99ABT||||||||||||";
            string omlTCD = $@"TCD|{test}^99ABT";

            string omlTestString = omlORC + '\r' + omlTQ1 + '\r' + omlOBR + '\r'+ omlTCD;

            return omlTestString;
        }
        #endregion

        #region Отправка сообщения OML^O33, когда задание не найдено
        static void NegativeOMLSending(Socket client_, Encoding utf8, string rid, string omlDate)
        {
            // guid ответного сообщения
            Guid guid = Guid.NewGuid();
            // кавычки
            string quot = "\"";

            string negomlMSH = $@"MSH|^~\&|||||{omlDate}||OML^O33^OML_O33|{guid}|P|2.5.1|||NE|AL||UNICODE UTF-8|||LAB-28^IHE";
            string negomlSPM = @"SPM|1|||" + quot + quot + $@"|||||||U^Unknown^HL70369";
            string negomlSAC = $@"SAC|||{rid}";
            string negomlORC = $@"ORC|DC||||||||{omlDate}";

            string negomlResponse = negomlMSH + '\r' + negomlSPM + '\r' + negomlSAC + '\r' + negomlORC;

            // строка в массив байт
            byte[] SendingMessageBytes;
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(negomlResponse), CR, FS, CR);
            // отправляем прибору
            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending Negative query acknowledgment OML^O33 to analyzer");
                ExchangeLog("LIS (driver as CLI):" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }

        #endregion

        #region ответ на сообщение с результатом ACK^R22 Acknowledgment (Query Response)
        static void ACKR22Sending(Socket client_, Encoding utf8, string id)
        {
            // ACK^R22 sending
            DateTime now = DateTime.Now;
            string ackDate = now.ToString("yyyyMMddHHmmss");
            // guid ответного сообщения
            Guid guid = Guid.NewGuid();

            // шаблон ответа ACK^R22 в формате HL7 (по мануалу)
            string ackMSH = $@"MSH|^~\&|||||{ackDate}||ACK^R22^ACK|{guid}|P|2.5.1||||||UNICODE UTF-8|||LAB-29^IHE";
            string ackMSA = $@"MSA|AA|{id}";

            string ackResponse = ackMSH + '\r' + ackMSA;

            // строка подтверждения в массив байт
            byte[] SendingMessageBytes;
            SendingMessageBytes = ConcatByteArray(VT, utf8.GetBytes(ackResponse), CR, FS, CR);

            // отправляем прибору
            if (client_.Poll(1, SelectMode.SelectWrite))
            {
                client_.Send(SendingMessageBytes);
                ExchangeLog($"Sending response ACK^R22 to analyzer");
                ExchangeLog("LIS (driver as SRV):" + "\n" + utf8.GetString(SendingMessageBytes));
                ExchangeLog($"");
            }
        }
        #endregion

        #region Отправка задания прибору ASTM
        static void OrderDownload(Socket client_, Encoding utf8, string rid)
        {
            string orderH = $@"H|\^&||||||||||P";
            string orderP = $@"P|1|||PID0001|Testov^Test^Q||20140414|M|||||Dr. Smith||||||||||||FNKC";
            string orderO = $@"O|1|{rid}||^^^658|||||||A||||||||||||||O";
            string orderC = $@"C|1|L|Order comment.|G";
            string orderL = $@"L|1";

            string ackResponse = "";

            ackResponse = orderH + '\r' + orderP;
        }
        #endregion

        #endregion

        #region получение данных по заявке и отправка прибору задания OML^O33 клиентом драйвера 
        public static void GetRequestFromDB(Socket client_, Encoding utf8, string id, string RIDPar)
        {
            // переменные для данных из CGM
            string PID = "";
            string PatientSurname = "";
            string PatientName = "";
            string FullName = "";
            string PatientSex = "";
            string PatientBirthDay = "";
            string LISTestCode = "";
            DateTime PatientBirthDayDate = new DateTime();
            DateTime RegistrationDateDate = DateTime.Now;
            DateTime SampleDateDate = DateTime.Now;
            string SampleDate = "";
            bool RIDExists = false;
            // строка с заданиями (блок сообщения с тестами OML) для прибора
            string omlOrderString = "";
            DateTime now = DateTime.Now;
            string omlDate = now.ToString("yyyyMMddHHmmss");


            string CGMConnectionString = ConfigurationManager.ConnectionStrings["CGMConnection"].ConnectionString;
            CGMConnectionString = String.Concat(CGMConnectionString, $"User Id = {user}; Password = {password}");
            try
            {
                using (SqlConnection CGMconnection = new SqlConnection(CGMConnectionString))
                {
                    CGMconnection.Open();
                    #region ищем RID и получаем данные по нему из БД
                    //ищем RID в базе
                    SqlCommand RequetDataCommand = new SqlCommand(
                       "SELECT TOP 1" +
                         "p.pop_pid AS PID, p.pop_enamn AS PatientSurname, p.pop_fnamn AS PatientName, p.pop_fdatum AS PatientBirthday, " +
                         "CASE WHEN p.pop_kon = 'K' THEN 'F' ELSE 'M' END AS PatientSex, " +
                         "r.rem_ank_dttm AS RegistrationDate " +
                       "FROM dbo.remiss (NOLOCK) r " +
                         "INNER JOIN dbo.pop (NOLOCK) p ON p.pop_pid = r.pop_pid " +
                       "WHERE r.rem_deaktiv = 'O' " +
                         $"AND r.rem_rid IN ('{RIDPar}') " +
                         "AND r.rem_ank_dttm IS NOT NULL ", CGMconnection);
                    SqlDataReader Reader = RequetDataCommand.ExecuteReader();

                    // если такой ШК есть
                    if (Reader.HasRows)
                    {
                        RIDExists = true;
                        // получаем данные по заявке
                        while (Reader.Read())
                        {
                            if (!Reader.IsDBNull(0)) { PID = Reader.GetString(0); };
                            if (!Reader.IsDBNull(1)) { PatientSurname = Reader.GetString(1); };
                            if (!Reader.IsDBNull(2)) { PatientName = Reader.GetString(2); };
                            if (!Reader.IsDBNull(3))
                            {
                                PatientBirthDayDate = Reader.GetDateTime(3);
                                //PatientBirthDay = PatientBirthDayDate.Year + CheckZero(PatientBirthDayDate.Month) + CheckZero(PatientBirthDayDate.Day);
                                PatientBirthDay = PatientBirthDayDate.Year + CheckZero(PatientBirthDayDate.Month) + CheckZero(PatientBirthDayDate.Day) + CheckZero(PatientBirthDayDate.Hour)
                                                  + CheckZero(PatientBirthDayDate.Minute) + CheckZero(PatientBirthDayDate.Second); ;
                            }
                            if (!Reader.IsDBNull(4)) { PatientSex = Reader.GetString(4); };

                            if (!Reader.IsDBNull(5))
                            {
                                RegistrationDateDate = Reader.GetDateTime(5);
                            };
                        }
                    }
                    Reader.Close();
                    #endregion

                    #region есть ли тесты в задании - формируем строку с тестами для отправки в сообщении OML
                    // если шк есть, получаем тесты
                    if (RIDExists)
                    {
                        SqlCommand TestCodeCommand = new SqlCommand(
                            "SELECT b.ana_analyskod, prov.pro_provdat " +
                            "FROM dbo.remiss (NOLOCK) r " +
                              "INNER JOIN dbo.bestall (NOLOCK) b ON b.rem_id = r.rem_id " +
                              "INNER JOIN dbo.prov (NOLOCK) prov ON prov.pro_id = b.pro_id " +
                            "WHERE r.rem_deaktiv = 'O' " +
                            $"AND r.rem_rid IN('{RIDPar}') " +
                            //"AND r.rem_ank_dttm IS NOT NULL", CGMconnection);
                        
                        
                            "AND r.rem_ank_dttm IS NOT NULL " +
                            "AND b.bes_t_dttm IS NULL", CGMconnection); // bes_t_dttm дата теста, если ее нет, нет и результата, берем только эти тесты
                            
                            
                        SqlDataReader TestsReader = TestCodeCommand.ExecuteReader();

                        ExchangeLog("RID exists.");

                        // Если задания есть
                        if (TestsReader.HasRows)
                        {
                            while (TestsReader.Read())
                            {
                                if (!TestsReader.IsDBNull(0))
                                {
                                    LISTestCode = TestsReader.GetString(0);
                                    // преобразуем код теста в код, понятный анализатору
                                    string AnalyzerTestCode = TranslateToAnalyzerCodes(LISTestCode);

                                    //ExchangeLog($"Test code {LISTestCode} converted to {AnalyzerTestCode}");

                                    if (AnalyzerTestCode != "")
                                    {
                                        ExchangeLog($"Test code {LISTestCode} converted to {AnalyzerTestCode}");

                                        if (omlOrderString == "")
                                        {
                                            //ExchangeLog("формируется сторка с тестами");
                                            omlOrderString = OMLCreateTestString(AnalyzerTestCode, omlDate);

                                        }
                                        else
                                        {
                                            omlOrderString = omlOrderString + '\r' + OMLCreateTestString(AnalyzerTestCode, omlDate);
                                        }
                                    }
                                    else
                                    {
                                        ExchangeLog($"Test code {LISTestCode} could not be converted. The test is not configured to be transmitted to analyzer.");
                                    }

                                }
                                // Sample date from prov table
                                SampleDateDate = TestsReader.GetDateTime(1);
                                SampleDate = SampleDateDate.Year + CheckZero(SampleDateDate.Month) + CheckZero(SampleDateDate.Day) + CheckZero(SampleDateDate.Hour)
                                            + CheckZero(SampleDateDate.Minute) + CheckZero(SampleDateDate.Second);
                            }
                        }
                        TestsReader.Close();
                    }
                    #endregion

                    CGMconnection.Close();
                }

                // Если ШК существует, то отправляем задание прибору
                if (RIDExists)
                {
                    ExchangeLog("Order exists");
                    FullName = PatientSurname + '^' + PatientName;
                    // отправляем прибору задание и демографию пациента
                    //ExchangeLog("Sending request order OML^O33 to analyzer");
                    OMLSending(client_, utf8, id, RIDPar, PID, PatientName, PatientSurname, PatientBirthDay, PatientSex, SampleDate, omlOrderString, omlDate);
                }
                else
                {
                    // Negative query acknowledgment
                    ExchangeLog("There is NO order for this RID.");
                    ExchangeLog("Sending Negative query acknowledgment OML^O33 to analyzer");
                    NegativeOMLSending(client_, utf8, RIDPar, omlDate);
                }
               
                //ExchangeLog("Sending request order OML^O33 to analyzer");

            }
            catch (Exception ex)
            {
                //Console.WriteLine(ex);
                ServiceLog($"{ex}");
            }
        }

        #endregion

        #region Функция обработки файлов с результатами и создания файлов для службы, которая разберет файл и запишет данные в CGM
        static void ResultsProcessing()
        {
            while (ServiceIsActive)
            {
                try
                {
                    #region папки архива, результатов и ошибок

                    string OutFolder = ConfigurationManager.AppSettings["FolderOut"];
                    // архивная папка
                    string ArchivePath = AnalyzerResultPath + @"\Archive";
                    // папка для ошибок
                    string ErrorPath = AnalyzerResultPath + @"\Error";
                    // папка для файлов с результатами для CGM
                    string CGMPath = AnalyzerResultPath + @"\CGM";

                    if (!Directory.Exists(ArchivePath))
                    {
                        Directory.CreateDirectory(ArchivePath);
                    }

                    if (!Directory.Exists(ErrorPath))
                    {
                        Directory.CreateDirectory(ErrorPath);
                    }

                    if (!Directory.Exists(CGMPath))
                    {
                        Directory.CreateDirectory(CGMPath);
                    }
                    #endregion

                    // строки для формирования файла (psm файла) с результатами для службы,
                    // которая разбирает файлы и записывает результаты в CGM
                    string MessageHead = "";
                    string MessageTest = "";
                    string AllMessage = "";

                    // поолучаем список всех файлов в текущей папке
                    string[] Files = Directory.GetFiles(AnalyzerResultPath, "*.res");

                    // шаблоны регулярных выражений для поиска данных
                    string RIDPattern = @"SAC[|][|][|](?<RID>\d+)[|]\S*";
                    string TestPattern = @"OBX[|]\d+[|]ST[|](?<Test>.+)[@]99ABT[|]1";
                    string ResultPattern = @"OBX[|]\d+[|]ST[|].*[|]1[|](?<Result>[<>]?\s?\S+)[|]\S+UCUM";

                    Regex RIDRegex = new Regex(RIDPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                    Regex TestRegex = new Regex(TestPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                    Regex ResultRegex = new Regex(ResultPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));

                    // пробегаем по файлам
                    foreach (string file in Files)
                    {
                        FileResultLog(file);
                        string[] lines = System.IO.File.ReadAllLines(file);
                        string RID = "";
                        string Test = "";

                        // обрезаем только имя текущего файла
                        string FileName = file.Substring(AnalyzerResultPath.Length + 1);
                        // название файла .ок, который должен создаваться вместе с результирующим для обработки службой FileGetterService
                        string OkFileName = "";

                        // проходим по строкам в файле
                        foreach (string line in lines)
                        {
                            string line_ = line.Replace("^", "@");
                            Match RIDMatch = RIDRegex.Match(line_);
                            Match TestMatch = TestRegex.Match(line_);
                            Match ResultMatch = ResultRegex.Match(line_);

                            // поиск RID в строке
                            if (RIDMatch.Success)
                            {
                                RID = RIDMatch.Result("${RID}");
                                FileResultLog($"Заявка № {RID}");
                                MessageHead = $"O|1|{RID}||ALL|R|20240101000100|||||X||||ALL||||||||||F";
                            }
                            else
                            {
                                //FileResultLog("RID не найден");
                                //FileToErrorPath = true;
                            }

                            // поиск теста в строке
                            if (TestMatch.Success)
                            {
                                Test = TestMatch.Result("${Test}");
                                // преобразуем тест в код теста PSM
                                Test = Test.Replace("@", "^");
                                string PSMTestCode = TranslateToPSMCodes(Test);
                                string Result = "";
                                if (ResultMatch.Success)
                                {
                                    Result = ResultMatch.Result("${Result}");
                                    if (PSMTestCode == "")
                                    {
                                        FileResultLog($"Код анализатора {Test} не интерпретирован в PSMV2 код.");
                                        FileResultLog($"{Test} - результат: {Result}");
                                    }
                                    else
                                    {
                                        FileResultLog($"PSMV2 код: {PSMTestCode}");
                                        FileResultLog($"{Test} - результат: {Result}");
                                    }
                                }

                                // если код тест был интерпретирован
                                if ((PSMTestCode != "") && (Result != ""))
                                {
                                    // формируем строку с ответом для результирующего файла
                                    MessageTest = MessageTest + $"R|1|^^^{PSMTestCode}^^^^{AnalyzerCode}|{Result}|||N||F||ALINITY^||20230101000001|{AnalyzerCode}" + "\r";
                                }
                            }
                        }

                        // получаем название файла .ок на основании файла с результатом
                        if (FileName.IndexOf(".") != -1)
                        {
                            OkFileName = FileName.Split('.')[0] + ".ok";
                        }

                        // если строки с результатами и с ШК не пустые, значит формируем результирующий файл
                        if (MessageHead != "" && MessageTest != "")
                        {
                            try
                            {
                                // собираем полное сообщение с результатом
                                AllMessage = MessageHead + "\r" + MessageTest;

                                FileResultLog(AllMessage);

                                // создаем файл для записи результата в папке для рез-тов
                                if (!File.Exists(OutFolder + @"\" + FileName))
                                {
                                    using (StreamWriter sw = File.CreateText(OutFolder + @"\" + FileName))
                                    {
                                        foreach (string msg in AllMessage.Split('\r'))
                                        {
                                            sw.WriteLine(msg);
                                        }
                                    }
                                }
                                else
                                {
                                    File.Delete(OutFolder + @"\" + FileName);
                                    using (StreamWriter sw = File.CreateText(OutFolder + @"\" + FileName))
                                    {
                                        foreach (string msg in AllMessage.Split('\r'))
                                        {
                                            sw.WriteLine(msg);
                                        }
                                    }
                                }

                                // создаем .ok файл в папке для рез-тов
                                if (OkFileName != "")
                                {
                                    if (!File.Exists(OutFolder + @"\" + OkFileName))
                                    {
                                        using (StreamWriter sw = File.CreateText(OutFolder + @"\" + OkFileName))
                                        {
                                            sw.WriteLine("ok");
                                        }
                                    }
                                    else
                                    {
                                        File.Delete(OutFolder + OkFileName);
                                        using (StreamWriter sw = File.CreateText(OutFolder + @"\" + OkFileName))
                                        {
                                            sw.WriteLine("ok");
                                        }
                                    }
                                }

                                // помещение файла в архивную папку
                                if (File.Exists(ArchivePath + @"\" + FileName))
                                {
                                    File.Delete(ArchivePath + @"\" + FileName);
                                }
                                File.Move(file, ArchivePath + @"\" + FileName);

                                FileResultLog("Файл обработан и перемещен в папку Archive");
                                FileResultLog("");
                            }
                            catch(Exception ex)
                            {
                                FileResultLog(ex.ToString());
                                // помещение файла в папку с ошибками
                                if (File.Exists(ErrorPath + @"\" + FileName))
                                {
                                    File.Delete(ErrorPath + @"\" + FileName);
                                }
                                File.Move(file, ErrorPath + @"\" + FileName);

                                FileResultLog("Ошибка обработки файла. Файл перемещен в папку Error");
                                FileResultLog("");
                            }
                        }
                        else
                        {
                            // помещение файла в папку с ошибками
                            if (File.Exists(ErrorPath + @"\" + FileName))
                            {
                                File.Delete(ErrorPath + @"\" + FileName);
                            }
                            File.Move(file, ErrorPath + @"\" + FileName);

                            FileResultLog("Ошибка обработки файла. Файл перемещен в папку Error");
                            FileResultLog("");
                        }
                    }
                }
                catch (Exception ex)
                {
                    FileResultLog(ex.ToString());
                }

                Thread.Sleep(1000);
            }
        }
        #endregion

        #region TCP сервер драйвера (HL7)
        static void TCPServer()
        {
            try
            {
                while (ServiceIsActive)
                {
                    #region Настраиваем TCP клиент для передачи данных на прибор

                    ServiceLog("TCP клиент драйвера запущен.");
                    Console.WriteLine("TCP клиент запущен");
                    IPAddress tcpClient_ip = IPAddress.Parse(analyzerIPadress);
                    // конечная точка - объединение IP-адреса прибора и порта 50020
                    IPEndPoint receiving_endpoint = new IPEndPoint(tcpClient_ip, receiving_port);
                    // сокет для отправки в канал получения данных от драйвера
                    Socket sending_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                    try
                    {
                        // пытаемся подключиться
                        sending_socket.Connect(receiving_endpoint);
                        Console.WriteLine("Подключение к серверу установлено.");
                        Console.WriteLine($"Адрес сервера: {sending_socket.RemoteEndPoint}");
                        Console.WriteLine($"Адрес клиента: {sending_socket.LocalEndPoint}");
                        ServiceLog("Подключение к серверу установлено.");
                        ServiceLog($"Адрес сервера: {sending_socket.RemoteEndPoint}");
                        ServiceLog($"Адрес клиента: {sending_socket.LocalEndPoint}");
                    }
                    catch (Exception ex)
                    {
                        ServiceLog(ex.ToString());
                    }

                    #endregion

                    IPAddress ip = IPAddress.Parse(IPadress);
                    // локальная точка EndPoint, на которой сокет будет принимать подключения от клиентов
                    EndPoint endpoint = new IPEndPoint(ip, port);
                    // создаем сокет
                    Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    // связываем сокет с локальной точкой endpoint 
                    socket.Bind(endpoint);

                    // получаем конечную точку, с которой связан сокет
                    Console.WriteLine(socket.LocalEndPoint);
                    ServiceLog(socket.LocalEndPoint.ToString());

                    // запуск прослушивания подключений
                    socket.Listen(1000);
                    Console.WriteLine("TCP Сервер запущен. Ожидание подключений...");
                    ServiceLog("TCP Сервер запущен. Ожидание подключений...");
                    // После начала прослушивания сокет готов принимать подключения
                    // получаем входящее подключение
                    Socket client = socket.Accept();

                    // получаем адрес клиента, который подключился к нашему tcp серверу
                    Console.WriteLine($"Адрес подключенного клиента: {client.RemoteEndPoint}");
                    ServiceLog($"Адрес подключенного клиента: {client.RemoteEndPoint}");

                    int ServerCount = 0; // счетчик

                    while (ServiceIsActive)
                    {
                        // нет данных для чтения и соединение не активно
                        if (client.Poll(1, SelectMode.SelectRead) && client.Available == 0)
                        {
                            ServiceLog("Ожидание переподключения");
                            client = socket.Accept();
                            //ServiceLog("Ожидание переподключения");
                        }

                        // если клиент ничего не посылает
                        if (client.Available == 0)
                        {
                            ServerCount++;
                            if (ServerCount == 100)
                            {
                                ServerCount = 0;
                                //ServiceLog("Текущее время: " + DateTime.Now.ToString("hh:mm:ss") + " / " + DateTime.Now.TimeOfDay.ToString() + " / " + DateTime.Now.ToString("HH:mm:ss"));
                                //ServiceLog("Текущее время UTC: " + DateTime.UtcNow.ToString("hh:mm:ss") + " / " + DateTime.UtcNow.ToString());
                                ServiceLog("Свойства сокета: " +
                                            $"Blocking: {client.Blocking}; " +
                                            $"Connected: {client.Connected}; " +
                                            $"RemoteEndPoint: {client.RemoteEndPoint}; " +
                                            $"LocalEndPoint: {client.LocalEndPoint}; ");
                                ServiceLog("Состояние сокета: " +
                                           $"handler.Available {client.Available}; " +
                                           $"SelectRead: {client.Poll(1, SelectMode.SelectRead)}; " +
                                           $"SelectWrite: {client.Poll(1, SelectMode.SelectWrite)}; " +
                                           $"SelectError: {client.Poll(1, SelectMode.SelectError)};");
                                ServiceLog("Прослушивание сокета...");
                                ServiceLog("");
                            }
                        }
                        else
                        {
                            // UTF8 encoder
                            Encoding utf8 = Encoding.UTF8;
                            // количество полученных байтов
                            int received_bytes = 0;
                            // буфер для получения данных
                            //byte[] received_data = new byte[1024];
                            byte[] received_data = new byte[4096];
                            //byte[] received_data = new byte[4608];
                            // StringBuilder для склеивания полученных данных в одну строку
                            var messageFromAlinity = new StringBuilder();

                            ServiceLog("Свойства сокета: " + $"Blocking: {client.Blocking}; " + $"Connected: {client.Connected}; " + $"RemoteEndPoint: {client.RemoteEndPoint}; ");
                            // состояние сокета
                            ServiceLog("Состояние сокета: " +
                                           $"handler.Available {client.Available}; " +
                                           $"SelectRead: {client.Poll(1, SelectMode.SelectRead)}; " +
                                           $"SelectWrite: {client.Poll(1, SelectMode.SelectWrite)}; " +
                                           $"SelectError: {client.Poll(1, SelectMode.SelectError)};");
                            ServiceLog("Есть данные на сокете. Получение сообщения от анализатора.");
                            ServiceLog("");

                            // считываем, пока есть данные на сокете
                            do
                            {
                                received_bytes = client.Receive(received_data);
                                // GetString - декодирует последовательность байтов из указанного массива байтов в строку.
                                // преобразуем полученный набор байтов в строку
                                string ResponseMsg = Encoding.UTF8.GetString(received_data, 0, received_bytes);

                                // добавляем в StringBuilder
                                messageFromAlinity.Append(ResponseMsg);
                                ExchangeLog("Analyzer (driver as SRV):" + "\n" + messageFromAlinity.ToString());
                            }
                            while (client.Available > 0);

                            // нужно заменить птички, иначе рег.выражение не работает
                            string messageAlinity = messageFromAlinity.ToString().Replace("^", "@");

                            // Определяем тип сообщения, которое отправил прибор
                            #region определение типа сообщения от прибора

                            ExchangeLog($"Message type identification.");

                            #region Типы сообщений, установки теста соединения и доступных методик (в данный момент отключено на приборе)
                            // Тип сообщения NMD - установка соединения с ЛИС
                            string NMDPattern = @"MSH[|]\S+[|](?<type>\w+)@N02@NMD_N02[|]\S+[|]";
                            Regex NMDRegex = new Regex(NMDPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string NMD = "";

                            // Поиск query tag
                            string QueryTagPattern = @"QPD[|].*[|](?<tag>\d+)[|]\d+";
                            Regex QueryTagRegex = new Regex(QueryTagPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string QueryTag = "";

                            Match NMDMatch = NMDRegex.Match(messageAlinity);

                            if (NMDMatch.Success)
                            {
                                NMD = NMDMatch.Result("${type}");
                                ExchangeLog($"Message type: {NMD}");

                                // найдем query tag
                                Match QueryTagMatch = QueryTagRegex.Match(messageAlinity);

                                if (QueryTagMatch.Success)
                                {
                                    QueryTag = QueryTagMatch.Result("${tag}");
                                }
                            }

                            // Тип сообщения TCU - прибор отправляет методики, которые доступны для выполнения
                            string TCUPattern = @"MSH[|]\S+[|](?<type>\w+)@U10@TCU_U10[|]\S+[|]";
                            Regex TCURegex = new Regex(TCUPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string TCU = "";

                            Match TCUMatch = TCURegex.Match(messageAlinity);

                            if (TCUMatch.Success)
                            {
                                TCU = TCUMatch.Result("${type}");
                                ExchangeLog($"Message type: {TCU}");
                            }
                            #endregion

                            // Тип сообщения QBP - запрос задания
                            string QBPPattern = @"MSH[|]\S+[|](?<type>\w+)@Q11@QBP_Q11[|]\S+[|]P|2.5.1[|]\S+";
                            Regex QBPRegex = new Regex(QBPPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string QBP = "";

                            Match QBPMatch = QBPRegex.Match(messageAlinity);

                            if (QBPMatch.Success)
                            {
                                QBP = QBPMatch.Result("${type}");
                                //ExchangeLog($"Message type: {QBP} - Order Query");
                            }

                            // Тип сообщения OUL - сообщение с результатом
                            string OULPattern = @"MSH[|]\S+[|](?<type>\w+)@R22@OUL_R22[|]\S+[|]P|2.5.1[|]\S+";
                            Regex OULRegex = new Regex(OULPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string OUL = "";

                            Match OULMatch = OULRegex.Match(messageAlinity);

                            if (OULMatch.Success)
                            {
                                OUL = OULMatch.Result("${type}");
                                //ExchangeLog($"Message type: {OUL} - Result");
                            }

                            #endregion

                            #region нахождение MessageId в сообщении анализатора
                            // шаблона для поиска Message Id в сообщении от прибора
                            string MessageIdPattern = @"\S+[|](?<MessageId>\S+)[|]P[|]2.5.1[|]";
                            Regex MessageIdRegex = new Regex(MessageIdPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                            string MessageId = "";

                            Match MessageIdMatch = MessageIdRegex.Match(messageAlinity);
                            if (MessageIdMatch.Success)
                            {
                                MessageId = MessageIdMatch.Result("${MessageId}");
                                ExchangeLog($"Message ID : {MessageId}");
                            }
                            #endregion

                            #region если сообщение NMD или TCU (пока не нужно)
                            // если сообщение с тестом соединения - NMD
                            if (NMD == "NMD")
                            {
                                // формируем файл с результатом
                                //MakeAnalyzerResultFile(messageAlinity.ToString());
                                // отправляем прибору подтверждение получения - ACK
                                ACKNO2Sending(sending_socket, utf8, MessageId);
                                // Thread.Sleep(2000);
                                //NMDNO2Sending(client, utf8, MessageId);
                            }

                            // если сообщение с доступными методиками - TCU
                            if (TCU == "TCU")
                            {
                                // формируем файл с результатом
                                //MakeAnalyzerResultFile(messageAlinity.ToString());
                                // отправляем прибору подтверждение получения - ACK
                                ACKU10Sending(sending_socket, utf8, MessageId);
                            }
                            #endregion

                            // если запрос задания - QBP
                            if (QBP == "QBP")
                            {
                                ExchangeLog($"Message type: {QBP} - Order Query");
                                // шаблона для поиска RID в сообщении от прибора (QBP)
                                string RIDPattern = @"QPD[|].*[|](?<RID>\d+)";
                                Regex RIDRegex = new Regex(RIDPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                                string RID = "";

                                Match RIDMatch = RIDRegex.Match(messageAlinity);

                                if (RIDMatch.Success)
                                {
                                    RID = RIDMatch.Result("${RID}");
                                    ExchangeLog($"Request from LIS");
                                    ExchangeLog($"RID: {RID}");
                                }

                                // Поиск query tag
                                string QTagPattern = @"QPD[|].*[|](?<tag>\d+)[|]";
                                Regex QTagRegex = new Regex(QTagPattern, RegexOptions.None, TimeSpan.FromMilliseconds(150));
                                string QTag = "";

                                // найдем query tag
                                Match QTagMatch = QTagRegex.Match(messageAlinity);

                                if (QTagMatch.Success)
                                {
                                    QTag = QTagMatch.Result("${tag}");
                                    ExchangeLog($"Tag: {QTag}");
                                }

                                // отправка подтверждения RSP на запрос QBP
                                // отправка сервером драйвера 
                                RSPSending(client, utf8, MessageId, QTag, RID);

                                // получение данных по заявке и отправка задания OML после подтверждения RSP
                                // отправка клиентом драйвера
                                GetRequestFromDB(sending_socket, utf8, MessageId, RID);

                                if (sending_socket.Available > 0)
                                {
                                    //Console.WriteLine("Получаем ACK от сервера прибора");
                                    ExchangeLog("Receiving ACK from analyzer SRV");
                                    // буфер для получения данных
                                    var responseBytes = new byte[512];
                                    // получаем данные
                                    var bytes = sending_socket.Receive(responseBytes);
                                    // преобразуем полученные данные в строку
                                    string response = Encoding.UTF8.GetString(responseBytes, 0, bytes);
                                    // выводим данные на консоль
                                    //Console.WriteLine(response);
                                    ExchangeLog("Analyzer (driver as CLI):" + "\n" + response);
                                    //ExchangeLog(response);
                                }
                            }

                            // если сообщение с результатом - OUL
                            if (OUL == "OUL")
                            {
                                ExchangeLog($"Message type: {OUL} - Result");
                                ExchangeLog("Creating Result file");
                                // формируем файл с результатом
                                MakeAnalyzerResultFile(messageFromAlinity.ToString());

                                // отправка подтверждения ACK^R22
                                ACKR22Sending(client, utf8, MessageId);
                            }
                        }

                        Thread.Sleep(1000);
                    }
                }
            }
            catch (Exception ex)
            {
                ServiceLog($"Exception: {ex}");
            }
        }
        #endregion

        static void Main(string[] args)
        {
            ServiceIsActive = true;
            Console.WriteLine("Сервис начал работу.");
            ServiceLog("Сервис начал работу.");

            //TCP сервер для прибора
            Thread TCPServerThread = new Thread(new ThreadStart(TCPServer));
            TCPServerThread.Name = "TCPServer";
            TCPServerThread.Start();

            // Поток обработки результатов
            Thread ResultProcessingThread = new Thread(ResultsProcessing);
            ResultProcessingThread.Name = "ResultsProcessing";
            ResultProcessingThread.Start();

            Console.ReadLine();
        }
    }
}
