namespace Mesa.OAuth.Utility
{
    using System;
    using Mesa.OAuth.Framework;

    public static class Clock
    {
        private static Func<DateTime> nowFunc;

        static Clock ( )
        {
            nowFunc = ( ) => DateTime.Now;
        }

        public static string EpochString
        {
            get { return Now.Epoch ( ).ToString ( ); }
        }

        public static DateTime Now
        {
            get { return nowFunc ( ); }
        }

        public static IDisposable Freeze ( )
        {
            var now = Now;
            return ReplaceImplementation ( ( ) => now );
        }

        public static IDisposable FreezeAt ( DateTime time )
        {
            return ReplaceImplementation ( ( ) => time );
        }

        public static IDisposable ReplaceImplementation ( Func<DateTime> nowFunc )
        {
            var originalFunc = Clock.nowFunc;
            Clock.nowFunc = nowFunc;
            return new DisposableAction ( ( ) => Clock.nowFunc = originalFunc );
        }

        public static void Reset ( )
        {
            nowFunc = ( ) => DateTime.Now;
        }
    }
}