namespace Mesa.OAuth.KeyInterop
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text;

    internal class AsnParser
    {
        private readonly int initialCount;

        private readonly List<byte> octets;

        public AsnParser ( byte [ ] values )
        {
            this.octets = [ .. values ];

            this.initialCount = this.octets.Count;
        }

        public int CurrentPosition ( )
        {
            return this.initialCount - this.octets.Count;
        }

        public byte GetNextOctet ( )
        {
            int position = this.CurrentPosition ( );

            if ( 0 == this.RemainingBytes ( ) )
            {
                var sb = new StringBuilder ( "Incorrect Size. " );
                sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                1.ToString ( CultureInfo.InvariantCulture ) ,
                                this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                throw new BerDecodeException ( sb.ToString ( ) , position );
            }

            byte b = this.GetOctets ( 1 ) [ 0 ];

            return b;
        }

        public byte [ ] GetOctets ( int octetCount )
        {
            int position = this.CurrentPosition ( );

            if ( octetCount > this.RemainingBytes ( ) )
            {
                var sb = new StringBuilder ( "Incorrect Size. " );
                sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                octetCount.ToString ( CultureInfo.InvariantCulture ) ,
                                this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                throw new BerDecodeException ( sb.ToString ( ) , position );
            }

            byte [ ] values = new byte [ octetCount ];

            try
            {
                this.octets.CopyTo ( 0 , values , 0 , octetCount );
                this.octets.RemoveRange ( 0 , octetCount );
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }

            return values;
        }

        public bool IsNextBitString ( )
        {
            return 0x03 == this.octets [ 0 ];
        }

        public bool IsNextInteger ( )
        {
            return 0x02 == this.octets [ 0 ];
        }

        public bool IsNextNull ( )
        {
            return 0x05 == this.octets [ 0 ];
        }

        public bool IsNextOctetString ( )
        {
            return 0x04 == this.octets [ 0 ];
        }

        public bool IsNextSequence ( )
        {
            return 0x30 == this.octets [ 0 ];
        }

        public byte [ ] Next ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                int length = this.GetLength ( );

                if ( length > this.RemainingBytes ( ) )
                {
                    var sb = new StringBuilder ( "Incorrect Size. " );
                    sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                    length.ToString ( CultureInfo.InvariantCulture ) ,
                                    this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                return this.GetOctets ( length );
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public int NextBitString ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x03 != b )
                {
                    var sb = new StringBuilder ( "Expected Bit String. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                int length = this.GetLength ( );

                // We need to consume unused bits, which is the first
                //   octet of the remaing values
                b = this.octets [ 0 ];
                this.octets.RemoveAt ( 0 );
                length--;

                return 0x00 != b ? throw new BerDecodeException ( "The first octet of BitString must be 0" , position ) : length;
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public byte [ ] NextInteger ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x02 != b )
                {
                    var sb = new StringBuilder ( "Expected Integer. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                int length = this.GetLength ( );
                if ( length > this.RemainingBytes ( ) )
                {
                    var sb = new StringBuilder ( "Incorrect Integer Size. " );
                    sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                    length.ToString ( CultureInfo.InvariantCulture ) ,
                                    this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                return this.GetOctets ( length );
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public int NextNull ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x05 != b )
                {
                    var sb = new StringBuilder ( "Expected Null. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                // Next octet must be 0
                b = this.GetNextOctet ( );
                if ( 0x00 != b )
                {
                    var sb = new StringBuilder ( "Null has non-zero size. " );
                    sb.AppendFormat ( "Size: {0}" , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                return 0;
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public int NextOctetString ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x04 != b )
                {
                    var sb = new StringBuilder ( "Expected Octet String. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                int length = this.GetLength ( );
                if ( length > this.RemainingBytes ( ) )
                {
                    var sb = new StringBuilder ( "Incorrect Octet String Size. " );
                    sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                    length.ToString ( CultureInfo.InvariantCulture ) ,
                                    this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                return length;
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public byte [ ] NextOID ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x06 != b )
                {
                    var sb = new StringBuilder ( "Expected Object Identifier. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                int length = this.GetLength ( );
                if ( length > this.RemainingBytes ( ) )
                {
                    var sb = new StringBuilder ( "Incorrect Object Identifier Size. " );
                    sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                    length.ToString ( CultureInfo.InvariantCulture ) ,
                                    this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                byte [ ] values = new byte [ length ];

                for ( int i = 0 ; i < length ; i++ )
                {
                    values [ i ] = this.octets [ 0 ];
                    this.octets.RemoveAt ( 0 );
                }

                return values;
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public int NextSequence ( )
        {
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );
                if ( 0x30 != b )
                {
                    var sb = new StringBuilder ( "Expected Sequence. " );
                    sb.AppendFormat ( Constants.SpecifiedIdentifierMessageMask , b.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                int length = this.GetLength ( );
                if ( length > this.RemainingBytes ( ) )
                {
                    var sb = new StringBuilder ( Constants.IncorrectSequenceSizeMessage );
                    sb.AppendFormat ( Constants.SpecifiedRemainingMessageMask ,
                                    length.ToString ( CultureInfo.InvariantCulture ) ,
                                    this.RemainingBytes ( ).ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                return length;
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }
        }

        public int RemainingBytes ( )
        {
            return this.octets.Count;
        }

        private int GetLength ( )
        {
            int length = 0;

            // Checkpoint
            int position = this.CurrentPosition ( );

            try
            {
                byte b = this.GetNextOctet ( );

                if ( b == ( b & 0x7f ) )
                {
                    return b;
                }

                int i = b & 0x7f;

                if ( i > 4 )
                {
                    var sb = new StringBuilder ( "Invalid Length Encoding. " );
                    sb.AppendFormat ( "Length uses {0} octets" ,
                                    i.ToString ( CultureInfo.InvariantCulture ) );
                    throw new BerDecodeException ( sb.ToString ( ) , position );
                }

                while ( 0 != i-- )
                {
                    // shift left
                    length <<= 8;

                    length |= this.GetNextOctet ( );
                }
            }
            catch ( ArgumentOutOfRangeException ex )
            {
                throw new BerDecodeException ( Constants.ErrorParsingKeyMessage , position , ex );
            }

            return length;
        }
    }
}