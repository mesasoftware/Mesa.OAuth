namespace Mesa.OAuth.KeyInterop.ExtensionMethods
{
    using System;
    using System.Numerics;
    using System.Text;

    public static class BigIntegerExtensionMethods
    {
        public static string ToString ( this BigInteger value , int radix )
        {
            if ( radix is < 2 or > 36 )
            {
                throw new ArgumentOutOfRangeException ( nameof ( radix ) );
            }

            if ( value.IsZero )
            {
                return "0";
            }

            const string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            bool negative = value.Sign < 0;
            var v = BigInteger.Abs ( value );
            var sb = new StringBuilder ( );

            while ( v > 0 )
            {
                v = BigInteger.DivRem ( v , radix , out var remainder );
                sb.Insert ( 0 , chars [ ( int ) remainder ] );
            }

            if ( negative )
            {
                sb.Insert ( 0 , '-' );
            }

            return sb.ToString ( );
        }
    }
}