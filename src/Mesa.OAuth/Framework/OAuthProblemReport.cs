namespace Mesa.OAuth.Framework
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Text;
    using System.Web;

    [Serializable]
    public class OAuthProblemReport
    {
        private static readonly char [ ] separatorAmpersand = [ '&' ];

        private static readonly char [ ] separatorHyphen = [ '-' ];

        public OAuthProblemReport ( )
        {
            this.ParametersRejected = [ ];
            this.ParametersAbsent = [ ];
        }

        public OAuthProblemReport ( NameValueCollection parameters )
        {
            this.Problem = parameters [ Parameters.OAuth_Problem ];

            this.ProblemAdvice = parameters [ Parameters.OAuth_Problem_Advice ];

            this.ParametersAbsent = parameters.AllKeys.Any ( key => key == Parameters.OAuth_Parameters_Absent )
                                   ? ParseFormattedParameters ( parameters [ Parameters.OAuth_Parameters_Absent ] )
                                   : [ ];

            this.ParametersRejected = parameters.AllKeys.Any ( key => key == Parameters.OAuth_Parameters_Rejected )
                                     ? ParseFormattedParameters ( parameters [ Parameters.OAuth_Parameters_Rejected ] )
                                     : [ ];

            if ( parameters.AllKeys.Any ( key => key == Parameters.OAuth_Acceptable_Timestamps ) )
            {
                string [ ]? timeStamps = parameters [ Parameters.OAuth_Acceptable_Timestamps ]?.Split ( separatorHyphen );

                this.AcceptableTimeStampsFrom = DateTimeUtility.FromEpoch ( Convert.ToInt64 ( timeStamps?.ElementAtOrDefault ( 0 ) ) );
                this.AcceptableTimeStampsTo = DateTimeUtility.FromEpoch ( Convert.ToInt64 ( timeStamps?.ElementAtOrDefault ( 1 ) ) );
            }

            if ( parameters.AllKeys.Any ( key => key == Parameters.OAuth_Acceptable_Versions ) )
            {
                string [ ]? versions = parameters [ Parameters.OAuth_Acceptable_Versions ]?.Split ( separatorHyphen );

                this.AcceptableVersionFrom = versions?.ElementAtOrDefault ( 0 );
                this.AcceptableVersionTo = versions?.ElementAtOrDefault ( 1 );
            }
        }

        public OAuthProblemReport ( string formattedReport )
            : this ( HttpUtility.ParseQueryString ( formattedReport ) )
        {
        }

        public DateTime? AcceptableTimeStampsFrom { get; set; }

        public DateTime? AcceptableTimeStampsTo { get; set; }

        public string? AcceptableVersionFrom { get; set; }

        public string? AcceptableVersionTo { get; set; }

        public List<string>? ParametersAbsent { get; set; }

        public List<string>? ParametersRejected { get; set; }

        public string? Problem { get; set; }

        public string? ProblemAdvice { get; set; }

        public override string ToString ( )
        {
            if ( string.IsNullOrEmpty ( this.Problem ) )
            {
                throw Error.CantBuildProblemReportWhenProblemEmpty ( );
            }

            var response = new NameValueCollection
            {
                [ Parameters.OAuth_Problem ] = this.Problem
            };

            if ( !string.IsNullOrEmpty ( this.ProblemAdvice ) )
            {
                response [ Parameters.OAuth_Problem_Advice ] = this.ProblemAdvice.Replace ( "\r\n" , "\n" ).Replace ( "\r" , "\n" );
            }

            if ( this.ParametersAbsent?.Count > 0 )
            {
                response [ Parameters.OAuth_Parameters_Absent ] = FormatParameterNames ( this.ParametersAbsent );
            }

            if ( this.ParametersRejected?.Count > 0 )
            {
                response [ Parameters.OAuth_Parameters_Rejected ] = FormatParameterNames ( this.ParametersRejected );
            }

            if ( this.AcceptableTimeStampsFrom.HasValue && this.AcceptableTimeStampsTo.HasValue )
            {
                response [ Parameters.OAuth_Acceptable_Timestamps ] = string.Format ( "{0}-{1}" ,
                                                                                 this.AcceptableTimeStampsFrom.Value.Epoch ( ) ,
                                                                                 this.AcceptableTimeStampsTo.Value.Epoch ( ) );
            }

            if ( !( string.IsNullOrEmpty ( this.AcceptableVersionFrom ) || string.IsNullOrEmpty ( this.AcceptableVersionTo ) ) )
            {
                response [ Parameters.OAuth_Acceptable_Versions ] = string.Format ( "{0}-{1}" , this.AcceptableVersionFrom ,
                                                                               this.AcceptableVersionTo );
            }

            return UriUtility.FormatQueryString ( response );
        }

        private static string FormatParameterNames ( IEnumerable<string> names )
        {
            var builder = new StringBuilder ( );

            foreach ( string name in names )
            {
                if ( builder.Length > 0 )
                {
                    builder.Append ( '&' );
                }

                builder.Append ( UriUtility.UrlEncode ( name ) );
            }

            return builder.ToString ( );
        }

        private static List<string>? ParseFormattedParameters ( string? formattedList )
        {
            return formattedList?.Split ( separatorAmpersand , StringSplitOptions.RemoveEmptyEntries ).ToList ( );
        }
    }
}