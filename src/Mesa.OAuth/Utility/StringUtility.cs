namespace Mesa.OAuth.Utility
{
    public static class StringUtility
    {
        public static bool EqualsInConstantTime ( this string? value , string? other )
        {
            return !( value == null ^ other == null ) && ( value == null || ( value.Length == other?.Length && CompareStringsInConstantTime ( value , other ) ) );
        }

        private static bool CompareStringsInConstantTime ( string value , string other )
        {
            int result = 0;

            for ( int i = 0 ; i < value.Length ; i++ )
            {
                result |= value [ i ] ^ other [ i ];
            }

            return result == 0;
        }
    }
}