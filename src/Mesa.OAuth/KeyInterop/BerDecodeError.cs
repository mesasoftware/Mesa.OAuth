namespace Mesa.OAuth.KeyInterop
{
    using System;
    using System.Text;

    [Serializable]
    public sealed class BerDecodeException : Exception
    {
        private readonly int m_position;

        public BerDecodeException ( )
        {
        }

        public BerDecodeException ( string message )
            : base ( message )
        {
        }

        public BerDecodeException ( string message , Exception ex )
            : base ( message , ex )
        {
        }

        public BerDecodeException ( string message , int position )
            : base ( message )
        {
            this.m_position = position;
        }

        public BerDecodeException ( string message , int position , Exception ex )
            : base ( message , ex )
        {
            this.m_position = position;
        }

        public override string Message
        {
            get
            {
                var sb = new StringBuilder ( base.Message );

                sb.AppendFormat ( " (Position {0}){1}" ,
                                this.m_position , Environment.NewLine );

                return sb.ToString ( );
            }
        }

        public int Position
        {
            get { return this.m_position; }
        }
    }
}