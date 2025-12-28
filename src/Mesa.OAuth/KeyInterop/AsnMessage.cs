namespace Mesa.OAuth.KeyInterop
{
    using System;

    public class AsnMessage
    {
        private readonly string m_format;

        private readonly byte [ ] m_octets;

        public AsnMessage ( byte [ ] octets , string format )
        {
            this.m_octets = octets;
            this.m_format = format;
        }

        public int Length
        {
            get
            {
                return null == this.m_octets ? 0 : this.m_octets.Length;
            }
        }

        public byte [ ] GetBytes ( )
        {
            return this.m_octets ?? Array.Empty<byte> ( );
        }

        public string GetFormat ( )
        {
            return this.m_format;
        }
    }
}