using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Windows.Security.Credentials;

namespace IHS.MvvmCross.Plugins.Keychain.WindowsCommon
{
    public class WindowsCommonKeychain : IKeychain
    {
        public bool SetPassword(string password, string serviceName, string account)
        {
            var returnValue = false;
            try
            {
                // 
                //Add a credential to PasswordVault by supplying resource, username, and password 
                // 
                var vault = new PasswordVault();
                var credential = new PasswordCredential(serviceName, account, password);
                vault.Add(credential);
                returnValue = true;
            }
            catch (Exception)
            {
                returnValue = false;
            }                      
            return returnValue;
        }

        public string GetPassword(string serviceName, string account)
        {
            var returnValue = string.Empty;
            try
            {
                // 
                //Read a credential from PasswordVault by supplying resource or username 
                // 
                var vault = new PasswordVault();
                PasswordCredential credential = null;

                //Read by explicit resource and username name, result will be a single credential if it exists. Password will be returned. 
                // 
                credential = vault.Retrieve(serviceName, account);
                returnValue = credential.Password;
            }
            catch (Exception)
            {
 
            }
            return returnValue;
        }

        public bool DeletePassword(string serviceName, string account)
        {
            var returnValue = false;
            try
            {
                // 
                //Add a credential to PasswordVault by supplying resource, username, and password 
                // 
                var vault = new PasswordVault();
                var credential = new PasswordCredential(serviceName, account, string.Empty);
                vault.Add(credential);
                returnValue = true;
            }
            catch (Exception)
            {
                returnValue = false;
            }
            return returnValue;
        }

        public LoginDetails GetLoginDetails(string serviceName)
        {
            var returnValue = new LoginDetails();

            try
            {                
                var vault = new PasswordVault();
                IReadOnlyList<PasswordCredential> credentials = null;              
                credentials = vault.FindAllByResource(serviceName);
                                               
                if (null != credentials)
                {                    
                    foreach (var credential in credentials)
                    {                        
                        try
                        {
                            var credentialWithPassword = vault.Retrieve(credential.Resource, credential.UserName);
                            returnValue.Password = credentialWithPassword.Password;
                            returnValue.Username = credentialWithPassword.UserName;
                        }
                        catch (Exception)
                        {                           
                        }
                    }
                }
            }
            catch (Exception) // No stored credentials, so none to delete 
            {
                
            }
            return returnValue;
        }

        public bool DeleteAccount(string serviceName, string account)
        {
            var returnValue = false;
            var vault = new PasswordVault();
            var credential = vault.Retrieve(serviceName, account);
            try
            {
                vault.Remove(credential);
                returnValue = true;
            }
            catch (Exception)
            {

            }
            return returnValue;
        }
    }
}
