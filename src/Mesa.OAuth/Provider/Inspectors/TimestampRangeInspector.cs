namespace Mesa.OAuth.Provider.Inspectors
{
    using System;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Provider.Inspectors.Interfaces;
    using Mesa.OAuth.Utility;

    public class TimestampRangeInspector : IContextInspector
    {
        private readonly TimeSpan maxAfterNow;

        private readonly TimeSpan maxBeforeNow;

        private readonly Func<DateTime> nowFunc;

        public TimestampRangeInspector ( TimeSpan window )
            : this ( new TimeSpan ( window.Ticks / 2 ) , new TimeSpan ( window.Ticks / 2 ) )
        {
        }

        public TimestampRangeInspector ( TimeSpan maxBeforeNow , TimeSpan maxAfterNow )
            : this ( maxBeforeNow , maxAfterNow , ( ) => Clock.Now )
        {
        }

        public TimestampRangeInspector ( TimeSpan maxBeforeNow , TimeSpan maxAfterNow , Func<DateTime> nowFunc )
        {
            this.maxBeforeNow = maxBeforeNow;
            this.maxAfterNow = maxAfterNow;
            this.nowFunc = nowFunc;
        }

        public void InspectContext ( ProviderPhase phase , IOAuthContext context )
        {
            var timestamp = DateTimeUtility.FromEpoch ( Convert.ToInt32 ( context.Timestamp ) );
            var now = this.nowFunc ( );

            if ( now.Subtract ( this.maxBeforeNow ) > timestamp )
            {
                throw new OAuthException ( context , OAuthProblems.TimestampRefused ,
                                         string.Format (
                                             "The timestamp is to old, it must be at most {0} seconds before the servers current date and time" ,
                                             this.maxBeforeNow.TotalSeconds ) );
            }

            if ( now.Add ( this.maxAfterNow ) < timestamp )
            {
                throw new OAuthException ( context , OAuthProblems.TimestampRefused ,
                                         string.Format (
                                             "The timestamp is to far in the future, if must be at most {0} seconds after the server current date and time" ,
                                             this.maxAfterNow.TotalSeconds ) );
            }
        }
    }
}