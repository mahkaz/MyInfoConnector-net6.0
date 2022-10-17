namespace sg.gov.ndi.MyInfoConnector
{
    public interface IMyInfoConnector
    {
        (bool isValid, string[] messages) CheckConfiguration();

        /// <summary>
        /// Extract debug info to diagnose issues
        /// </summary>
        string[] GetDiagnosticInfo();

        string GetAuthoriseUrl(string redirectUrl, string state = null);

        string GetBCAuthoriseUrl(string redirectUri, string state, string bc_session);

        string GetPersonJson(string redirectUri, string authCode, string state, string txnNo = null);

    }
}
