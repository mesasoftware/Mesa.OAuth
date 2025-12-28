namespace Mesa.OAuth.Tests
{
    using System.Diagnostics;
    using System.Linq;
    using Mesa.OAuth.Utility;
    using Xunit;

    public class StringUtilityTests
    {
        [Theory]
        [InlineData ( "XY" , "XY" )]
        [InlineData ( "42" , "42" )]
        [InlineData ( "YX" , "XY" )]
        [InlineData ( "Y" , "Y" )]
        [InlineData ( "Y" , "X" )]
        [InlineData ( "X" , "Y" )]
        [InlineData ( "Xy" , "XY" )]
        [InlineData ( "yX" , "yX" )]
        [InlineData ( "XY" , "Y" )]
        [InlineData ( "X" , "XY" )]
        [InlineData ( "X" , "" )]
        [InlineData ( "" , "X" )]
        [InlineData ( null , "XY" )]
        [InlineData ( "XY" , null )]
        [InlineData ( null , null )]
        [InlineData ( "" , null )]
        [InlineData ( null , "" )]
        [InlineData ( "" , "" )]
        public void EqualsInConstantTime_GivenParameters_ShouldBeEqual ( string? value , string? other )
        {
            // Arrange.
            bool expected = string.Equals ( value , other );

            // Act.
            bool actual = value.EqualsInConstantTime ( other );

            // Assert.
            Assert.Equal ( expected , actual );
        }

        private static decimal CalculatePercentageDifference ( long [ ] rangesOfTime )
        {
            long maxTime = rangesOfTime.Max ( );

            long minTime = rangesOfTime.Min ( );

            return 1.0m - ( 1.0m / maxTime * minTime );
        }

        private static string GenerateTestString ( double percentMatch , int length )
        {
            int matchLength = ( int ) ( percentMatch * length );
            int nonMatchLength = length - matchLength;

            return nonMatchLength == 0 ? new string ( 'X' , length ) : new string ( 'X' , matchLength ) + new string ( 'Y' , nonMatchLength );
        }

        private static long TimeCompareValuesOverIterationsConstantTime ( string value , string other , int iterations )
        {
            var stopWatch = Stopwatch.StartNew ( );

            for ( int i = 0 ; i < iterations ; i++ )
            {
                value.EqualsInConstantTime ( other );
            }

            return stopWatch.ElapsedTicks;
        }

        private static long TimeCompareValuesOverIterationsStringEquals ( string value , string other , int iterations )
        {
            var stopWatch = Stopwatch.StartNew ( );

            for ( int i = 0 ; i < iterations ; i++ )
            {
                value.Equals ( other );
            }

            return stopWatch.ElapsedTicks;
        }
    }
}