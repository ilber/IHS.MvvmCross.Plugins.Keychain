using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Android.Content;
using Android.Runtime;
using Java.IO;
using Java.Security;
using Javax.Crypto;
using MvvmCross.Platform;
using MvvmCross.Platform.Droid;

namespace IHS.MvvmCross.Plugins.Keychain.Droid
{
	public class DroidKeychain : IKeychain
	{
		KeyStore _keyStore;

		KeyStore.PasswordProtection _passwordProtection;

		static readonly object fileLock = new object();

		const string FileName = "App.Accounts";

		char[] _userSelectedPassword;

		bool _keychainInitialized;

		Context _context;

		Context Context
		{
			get { return _context ?? (_context = Mvx.Resolve<IMvxAndroidGlobals>().ApplicationContext); }
			set { _context = value; }
		}

		public void Init(string protectionPassword)
		{
			if (string.IsNullOrWhiteSpace(protectionPassword))
			{
				throw new ArgumentException("Cannot initialize without protection password.", nameof(protectionPassword));
			}

			_userSelectedPassword = protectionPassword.ToCharArray();

			_keyStore = KeyStore.GetInstance(KeyStore.DefaultType);

			_passwordProtection = new KeyStore.PasswordProtection(_userSelectedPassword);

			try
			{
				lock (fileLock)
				{
					using (var s = Context.OpenFileInput(FileName))
					{
						_keyStore.Load(s, _userSelectedPassword);
					}
				}
			}
			catch (FileNotFoundException)
			{
				LoadEmptyKeyStore(_userSelectedPassword);
			}

			_keychainInitialized = true;
		}

		public bool SetPassword(string password, string serviceName, string account)
		{
			if (!_keychainInitialized)
			{
				throw new InvalidOperationException($"Call [{nameof(Init)}] before using the component");
			}

			var storedAccount = FindAccountsForService(serviceName).FirstOrDefault(ac => ac.Username == account);
			if (storedAccount != null)
			{
				storedAccount.Password = password;
			}
			else
			{
				storedAccount = new LoginDetails() { Password = password, Username = account };
			}

			Save(storedAccount, serviceName);

			return true;
		}

		public string GetPassword(string serviceName, string account)
		{
			if (!_keychainInitialized)
			{
				throw new InvalidOperationException($"Call [{nameof(Init)}] before using the component");
			}

			var storedAccount = FindAccountsForService(serviceName).FirstOrDefault(ac => ac.Username == account);
			return storedAccount != null ? storedAccount.Password : null;
		}

		public bool DeletePassword(string serviceName, string account)
		{
			if (!_keychainInitialized)
			{
				throw new InvalidOperationException($"Call [{nameof(Init)}] before using the component");
			}

			var storedAccount = FindAccountsForService(serviceName).FirstOrDefault(ac => ac.Username == account);
			if (storedAccount == null)
				return true;

			storedAccount.Password = string.Empty;
			Save(storedAccount, serviceName);

			return true;
		}

		public LoginDetails GetLoginDetails(string serviceName)
		{
			if (!_keychainInitialized)
			{
				throw new InvalidOperationException($"Call [{nameof(Init)}] before using the component");
			}

			var storedAccount = FindAccountsForService(serviceName).FirstOrDefault();

			return storedAccount;
		}

		public bool DeleteAccount(string serviceName, string account)
		{
			if (!_keychainInitialized)
			{
				throw new InvalidOperationException($"Call [{nameof(Init)}] before using the component");
			}

			var storedAccount = FindAccountsForService(serviceName).FirstOrDefault(ac => ac.Username == account);
			if (storedAccount == null)
				return true;

			Delete(storedAccount, serviceName);

			return true;
		}

		#region Port from Xamarin.Secutiry

		IEnumerable<LoginDetails> FindAccountsForService(string serviceId)
		{
			var r = new List<LoginDetails>();

			var postfix = "-" + serviceId;

			var aliases = _keyStore.Aliases();
			while (aliases.HasMoreElements)
			{
				var alias = aliases.NextElement().ToString();
				if (alias.EndsWith(postfix, StringComparison.Ordinal))
				{
					var e = _keyStore.GetEntry(alias, _passwordProtection) as KeyStore.SecretKeyEntry;
					if (e != null)
					{
						var bytes = e.SecretKey.GetEncoded();
						var serialized = Encoding.UTF8.GetString(bytes);
						var acct = LoginDetails.Deserialize(serialized);
						r.Add(acct);
					}
				}
			}

			r.Sort((a, b) => string.Compare(a.Username, b.Username, StringComparison.Ordinal));

			return r;
		}

		void Save(LoginDetails account, string serviceId)
		{
			var alias = MakeAlias(account, serviceId);

			var secretKey = new SecretAccount(account);
			var entry = new KeyStore.SecretKeyEntry(secretKey);
			_keyStore.SetEntry(alias, entry, _passwordProtection);

			Save();
		}

		void Delete(LoginDetails account, string serviceId)
		{
			var alias = MakeAlias(account, serviceId);

			_keyStore.DeleteEntry(alias);
			Save();
		}

		void Save()
		{
			lock (fileLock)
			{
				using (var s = Context.OpenFileOutput(FileName, FileCreationMode.Private))
				{
					_keyStore.Store(s, _userSelectedPassword);
				}
			}
		}

		static string MakeAlias(LoginDetails account, string serviceId)
		{
			return account.Username + "-" + serviceId;
		}

		class SecretAccount : Java.Lang.Object, ISecretKey
		{
			byte[] bytes;
			public SecretAccount(LoginDetails account)
			{
				bytes = System.Text.Encoding.UTF8.GetBytes(account.Serialize());
			}
			public byte[] GetEncoded()
			{
				return bytes;
			}
			public string Algorithm
			{
				get
				{
					return "RAW";
				}
			}
			public string Format
			{
				get
				{
					return "RAW";
				}
			}
		}

		static IntPtr id_load_Ljava_io_InputStream_arrayC;

		/// <summary>
		/// Work around Bug https://bugzilla.xamarin.com/show_bug.cgi?id=6766
		/// </summary>
		void LoadEmptyKeyStore(char[] password)
		{
			if (id_load_Ljava_io_InputStream_arrayC == IntPtr.Zero)
			{
				id_load_Ljava_io_InputStream_arrayC = JNIEnv.GetMethodID(_keyStore.Class.Handle, "load", "(Ljava/io/InputStream;[C)V");
			}
			IntPtr intPtr = IntPtr.Zero;
			IntPtr intPtr2 = JNIEnv.NewArray(password);
			JNIEnv.CallVoidMethod(_keyStore.Handle, id_load_Ljava_io_InputStream_arrayC, new JValue[]
				{
					new JValue (intPtr),
					new JValue (intPtr2)
				});
			JNIEnv.DeleteLocalRef(intPtr);
			if (password != null)
			{
				JNIEnv.CopyArray(intPtr2, password);
				JNIEnv.DeleteLocalRef(intPtr2);
			}
		}

		#endregion
	}
}
