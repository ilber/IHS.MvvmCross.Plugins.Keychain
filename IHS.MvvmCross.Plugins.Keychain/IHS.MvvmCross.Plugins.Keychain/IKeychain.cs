﻿namespace IHS.MvvmCross.Plugins.Keychain
{
    public interface IKeychain
    {
		void Init(string protectionPassword);
        bool SetPassword(string password, string serviceName, string account);
        string GetPassword(string serviceName, string account);
        bool DeletePassword(string serviceName, string account);
        LoginDetails GetLoginDetails(string serviceName);
        bool DeleteAccount(string serviceName, string account);
    }
}