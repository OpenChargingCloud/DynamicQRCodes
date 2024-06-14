
using System.Text;
using System.Security.Cryptography;

namespace cloud.charging.open.utils.QRCodes.TOTP
{

    /// <summary>
    /// The TOTP algorithm typically has a standard length of 6-8 digits and uses a defined set of characters
    /// (e.g., digits only for numeric TOTP, see RFC 6238).
    /// 
    /// Dynamic truncation method like as described in RFC 4226?
    /// 
    /// Standard TOTP uses digits only: "0123456789"
    /// </summary>
    public class QRCodeTOTPGenerator
    {

        private static String CalcTOTPSlot(Byte[]      SlotBytes,
                                           Byte        TOTPLength,
                                           String      Alphabet,
                                           HMACSHA256  hmac)
        {

            // .NET uses little-endian byte order!
            if (BitConverter.IsLittleEndian)
                Array.Reverse(SlotBytes);

            Console.WriteLine(String.Join("-", SlotBytes.Select(b => b.ToString())));

            var currentHash    = hmac.ComputeHash(SlotBytes);
            var stringBuilder  = new StringBuilder(TOTPLength);

            // For additional security start at a random offset
            // based on the last bit of the hash value (see RFCs)
            var offset         = currentHash[^1] & 0x0F;

            for (var i = 0; i < TOTPLength; i++)
                stringBuilder.Append(Alphabet[currentHash[(offset + i) % currentHash.Length] % Alphabet.Length]);

            return stringBuilder.ToString();

        }


        /// <summary>
        /// Calculate TOTP and the remaining time until the TOTP will change.
        /// </summary>
        /// <param name="SharedSecret"></param>
        /// <param name="ValidityTime"></param>
        /// <param name="TOTPLength"></param>
        /// <param name="Alphabet"></param>
        /// <param name="Timestamp"></param>
        /// <returns>The TOTP and the remaining time until the TOTP will change.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static (String    PreviousTOTP,
                       String    CurrentTOTP,
                       String    NextTOTP,
                       TimeSpan  RemainingTime)

            GenerateTOTPs(String     SharedSecret,
                          TimeSpan?  ValidityTime   = null,
                          Byte       TOTPLength     = 12,
                          String?    Alphabet       = null,
                          DateTime?  Timestamp      = null)

        {

            #region Initial Checks

            SharedSecret   = SharedSecret.Trim();
            ValidityTime ??= TimeSpan.FromSeconds(30);
            Alphabet     ??= "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            Alphabet       = Alphabet.Trim();

            if (String.IsNullOrEmpty(SharedSecret))
                throw new ArgumentNullException(nameof(SharedSecret),
                                                "The given shared secret must not be null or empty!");

            if (SharedSecret.Any(Char.IsWhiteSpace))
                throw new ArgumentException    ("The given shared secret must not contain any whitespace character!",
                                                nameof(Alphabet));

            if (SharedSecret.Length < 16)
                throw new ArgumentException    ("The length of the given shared secret must be at least 16 characters!",
                                                nameof(Alphabet));

            if (TOTPLength < 4)
                throw new ArgumentException    ("The expected length of the TOTP must be between 4 and 255 characters!",
                                                nameof(Alphabet));

            if (String.IsNullOrEmpty(Alphabet))
                throw new ArgumentNullException(nameof(Alphabet),
                                                "The given alphabet must not be null or empty!");

            if (Alphabet.Length < 4)
                throw new ArgumentException    ("The given alphabet must contain at least 4 characters!",
                                                nameof(Alphabet));

            if (Alphabet.Length != Alphabet.Distinct().Count())
                throw new ArgumentException    ("The given alphabet must not contain duplicate characters!",
                                                nameof(Alphabet));

            if (Alphabet.Any(Char.IsWhiteSpace))
                throw new ArgumentException    ("The given alphabet must not contain any whitespace character!",
                                                nameof(Alphabet));

            #endregion

            using var hmac       = new HMACSHA256(Encoding.UTF8.GetBytes(SharedSecret));

            var currentUnixTime  = (Timestamp.HasValue
                                        ? new DateTimeOffset(Timestamp.Value)
                                        : DateTimeOffset.UtcNow).ToUnixTimeSeconds();
            var currentSlot      = (UInt64) (currentUnixTime / ValidityTime.Value.TotalSeconds);
            var remainingTime    = TimeSpan.FromSeconds(
                                       (Int32) ValidityTime.Value.TotalSeconds
                                         -
                                       (currentUnixTime % (Int32) ValidityTime.Value.TotalSeconds)
                                   );

            var previousTOTP     = CalcTOTPSlot(BitConverter.GetBytes(currentSlot - 1), TOTPLength, Alphabet, hmac);
            var currentTOTP      = CalcTOTPSlot(BitConverter.GetBytes(currentSlot),     TOTPLength, Alphabet, hmac);
            var nextTOTP         = CalcTOTPSlot(BitConverter.GetBytes(currentSlot + 1), TOTPLength, Alphabet, hmac);

            return (previousTOTP,
                    currentTOTP,
                    nextTOTP,
                    remainingTime);

        }

        public static void Main(String[] Arguments)
        {

            Console.WriteLine($"Generated TOTP: {GenerateTOTPs(SharedSecret: "secure!Charging!")}");
            Console.WriteLine($"Generated TOTP: {GenerateTOTPs(SharedSecret: "secure!Charging!", Alphabet:     "0123456789")}");
            Console.WriteLine($"Generated TOTP: {GenerateTOTPs(SharedSecret: "secure!Charging!", TOTPLength:    32)}");
            Console.WriteLine($"Generated TOTP: {GenerateTOTPs(SharedSecret: "secure!Charging!", ValidityTime:  TimeSpan.FromMinutes(1))}");

        }

    }

}
