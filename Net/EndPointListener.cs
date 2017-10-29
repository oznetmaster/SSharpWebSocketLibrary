#region License

/*
 * EndPointListener.cs
 *
 * This code is derived from EndPointListener.cs (System.Net) of Mono
 * (http://www.mono-project.com).
 *
 * The MIT License
 *
 * Copyright (c) 2005 Novell, Inc. (http://www.novell.com)
 * Copyright (c) 2012-2016 sta.blockhead
 * Copyright © 2016 Nivloc Enterprises Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#endregion

#region Authors

/*
 * Authors:
 * - Gonzalo Paniagua Javier <gonzalo@novell.com>
 */

#endregion

#region Contributors

/*
 * Contributors:
 * - Liryna <liryna.stark@gmail.com>
 * - Nicholas Devenish
 */

#endregion

using System;
using System.Collections;
using System.Collections.Generic;
#if SSHARP
using Crestron.SimplSharp;
using Crestron.SimplSharp.CrestronIO;
using Crestron.SimplSharp.CrestronSockets;
using SocketException = SSMono.Net.Sockets.SocketException;
using SSMono.Threading;
using IAsyncResult = Crestron.SimplSharp.CrestronIO.IAsyncResult;
using AsyncCallback = Crestron.SimplSharp.CrestronIO.AsyncCallback;
using Environment = Crestron.SimplSharp.CrestronEnvironmentEx;
using SSMono.Web;
using SSMono.Security.Cryptography;
using SSMono.Security.Cryptography.X509Certificates;

#else
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
#endif

namespace WebSocketSharp.Net
	{
	internal sealed class EndPointListener
		{
		#region Private Fields

		private List<HttpListenerPrefix> _all; // host == '+'
		private static readonly string _defaultCertFolderPath;
		private IPEndPoint _endpoint;
		private Logger _logger;
		private Dictionary<HttpListenerPrefix, HttpListener> _prefixes;
		private bool _secure;
#if SSHARP
		private CrestronListenerSocket _socket;
#else
		private Socket _socket;
#endif
#if !NETCF || BCC || SSL
		private ServerSslConfiguration _sslConfig;
#endif
		private List<HttpListenerPrefix> _unhandled; // host == '*'
		private Dictionary<HttpConnection, HttpConnection> _unregistered;
		private object _unregisteredSync;

		#endregion

		#region Static Constructor

		static EndPointListener ()
			{
			_defaultCertFolderPath = Environment.GetFolderPath (Environment.SpecialFolder.ApplicationData);
			}

		#endregion

		#region Internal Constructors

		internal EndPointListener (IPEndPoint endpoint, bool secure, string certificateFolderPath,
#if !NETCF || BCC || SSL
		                           ServerSslConfiguration sslConfig,
#endif
		                           bool reuseAddress,
#if SSHARP
		                           EthernetAdapterType adapter,
#endif
		                           Logger logger)
			{
			_logger = logger;

#if !NETCF || BCC || SSL
			if (secure)
				{
				var cert = getCertificate (endpoint.Port, certificateFolderPath, sslConfig.ServerCertificate);

				if (cert == null)
					throw new ArgumentException ("No server certificate could be found.");

				_secure = true;
				_sslConfig = new ServerSslConfiguration (sslConfig);
				_sslConfig.ServerCertificate = cert;
				}
#endif

			_endpoint = endpoint;
			_prefixes = new Dictionary<HttpListenerPrefix, HttpListener> ();
			_unregistered = new Dictionary<HttpConnection, HttpConnection> ();
			_unregisteredSync = ((ICollection)_unregistered).SyncRoot;
#if SSHARP
			_socket = new CrestronListenerSocket (IPAddress.Any, endpoint.Port, 16, adapter);
#else
			_socket = new Socket (address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
			if (reuseAddress)
				_socket.SetSocketOption (SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
#endif

			_socket.Bind (endpoint);
			_socket.Listen (500);
			_socket.BeginAccept (onAccept, this);
			}

		#endregion

		#region Internal Properties

		/// <summary>
		/// Gets the logging functions.
		/// </summary>
		/// <remarks>
		/// The default logging level is <see cref="LogLevel.Error"/>. If you would like to change it,
		/// you should set the <c>Log.Level</c> property to any of the <see cref="LogLevel"/> enum
		/// values.
		/// </remarks>
		/// <value>
		/// A <see cref="Logger"/> that provides the logging functions.
		/// </value>
		internal Logger Log
			{
			get { return _logger; }
			}

		#endregion

		#region Public Properties

		public IPAddress Address
			{
			get { return _endpoint.Address; }
			}

		public bool IsSecure
			{
			get { return _secure; }
			}

		public int Port
			{
			get { return _endpoint.Port; }
			}

#if !NETCF || BCC || SSL
		public ServerSslConfiguration SslConfiguration
			{
			get { return _sslConfig; }
			}
#endif

		#endregion

		#region Private Methods

		private static void addSpecial (List<HttpListenerPrefix> prefixes, HttpListenerPrefix prefix)
			{
			var path = prefix.Path;
			foreach (var pref in prefixes)
				{
				if (pref.Path == path)
					throw new HttpListenerException (87, "The prefix is already in use.");
				}

			prefixes.Add (prefix);
			}

#if !NETCF || BCC || SSL
		private static RSACryptoServiceProvider createRSAFromFile (string filename)
			{
			byte[] pvk = null;
			using (var fs = File.Open (filename, FileMode.Open, FileAccess.Read, FileShare.Read))
				{
				pvk = new byte[fs.Length];
				fs.Read (pvk, 0, pvk.Length);
				}

			var rsa = new RSACryptoServiceProvider ();
			rsa.ImportCspBlob (pvk);

			return rsa;
			}

		private static X509Certificate2 getCertificate (int port, string folderPath, X509Certificate2 defaultCertificate)
			{
			if (folderPath == null || folderPath.Length == 0)
				folderPath = _defaultCertFolderPath;

			try
				{
				var cer = Path.Combine (folderPath, String.Format ("{0}.cer", port));
				var key = Path.Combine (folderPath, String.Format ("{0}.key", port));
				if (File.Exists (cer) && File.Exists (key))
					{
					var cert = new X509Certificate2 (cer);
					cert.PrivateKey = createRSAFromFile (key);

					return cert;
					}
				}
			catch
				{
				}

			return defaultCertificate;
			}
#endif

		private void leaveIfNoPrefix ()
			{
			if (_prefixes.Count > 0)
				return;

			var prefs = _unhandled;
			if (prefs != null && prefs.Count > 0)
				return;

			prefs = _all;
			if (prefs != null && prefs.Count > 0)
				return;

			EndPointManager.RemoveEndPoint (_endpoint);
			}

		private static void onAccept (IAsyncResult asyncResult)
			{
			var lsnr = (EndPointListener)asyncResult.AsyncState;

#if SSHARP
			CrestronServerSocket sock = null;
#else
			Socket sock = null;
#endif
			try
				{
				sock = lsnr._socket.EndAccept (asyncResult);
				}
			catch (SocketException sex)
				{
				lsnr._logger.Error (sex.Message);
				}
			catch (ObjectDisposedException)
				{
				return;
				}

			try
				{
				lsnr._socket.BeginAccept (onAccept, lsnr);
				}
			catch
				{
				if (sock != null)
					sock.Close ();

				return;
				}

			if (sock == null)
				return;

			processAccepted (sock, lsnr);
			}

#if SSHARP
		private static void processAccepted (CrestronServerSocket socket, EndPointListener listener)
#else
		private static void processAccepted (Socket socket, EndPointListener listener)
#endif
			{
			listener.Log.Debug ("processAccepted from: {0}", socket.RemoteEndPoint);

			HttpConnection conn = null;
			try
				{
				conn = new HttpConnection (socket, listener);
				lock (listener._unregisteredSync)
					listener._unregistered[conn] = conn;

				conn.BeginReadRequest ();
				}
			catch
				{
				if (conn != null)
					{
					conn.Close (true);
					return;
					}

				socket.Close ();
				}
			}

		private static bool removeSpecial (List<HttpListenerPrefix> prefixes, HttpListenerPrefix prefix)
			{
			var path = prefix.Path;
			var cnt = prefixes.Count;
			for (var i = 0; i < cnt; i++)
				{
				if (prefixes[i].Path == path)
					{
					prefixes.RemoveAt (i);
					return true;
					}
				}

			return false;
			}

		private static HttpListener searchHttpListenerFromSpecial (string path, List<HttpListenerPrefix> prefixes)
			{
			if (prefixes == null)
				return null;

			HttpListener bestMatch = null;

			var bestLen = -1;
			foreach (var pref in prefixes)
				{
				var prefPath = pref.Path;

				var len = prefPath.Length;
				if (len < bestLen)
					continue;

				if (path.StartsWith (prefPath))
					{
					bestLen = len;
					bestMatch = pref.Listener;
					}
				}

			return bestMatch;
			}

		#endregion

		#region Internal Methods

#if !NETCF || BCC || SSL
		internal static bool CertificateExists (int port, string folderPath)
			{
			if (folderPath == null || folderPath.Length == 0)
				folderPath = _defaultCertFolderPath;

			var cer = Path.Combine (folderPath, String.Format ("{0}.cer", port));
			var key = Path.Combine (folderPath, String.Format ("{0}.key", port));

			return File.Exists (cer) && File.Exists (key);
			}
#endif

		internal void RemoveConnection (HttpConnection connection)
			{
			lock (_unregisteredSync)
				_unregistered.Remove (connection);
			}

		internal bool TrySearchHttpListener (Uri uri, out HttpListener listener)
			{
			listener = null;

			if (uri == null)
				return false;

			var host = uri.Host;
			var dns = Uri.CheckHostName (host) == UriHostNameType.Dns;
			var port = uri.Port.ToString ();
#if SSHARP
			var path = Crestron.SimplSharp.Net.HttpUtility.UrlDecode (uri.AbsolutePath);
#else
			var path = HttpUtility.UrlDecode (uri.AbsolutePath);
#endif
			var pathSlash = path[path.Length - 1] != '/' ? path + "/" : path;

			if (host != null && host.Length > 0)
				{
				var bestLen = -1;
				foreach (var pref in _prefixes.Keys)
					{
					if (dns)
						{
						var prefHost = pref.Host;
						if (Uri.CheckHostName (prefHost) == UriHostNameType.Dns && prefHost != host)
							continue;
						}

					if (pref.Port != port)
						continue;

					var prefPath = pref.Path;

					var len = prefPath.Length;
					if (len < bestLen)
						continue;

					if (path.StartsWith (prefPath) || pathSlash.StartsWith (prefPath))
						{
						bestLen = len;
						listener = _prefixes[pref];
						}
					}

				if (bestLen != -1)
					return true;
				}

			var prefs = _unhandled;
			listener = searchHttpListenerFromSpecial (path, prefs);
			if (listener == null && pathSlash != path)
				listener = searchHttpListenerFromSpecial (pathSlash, prefs);

			if (listener != null)
				return true;

			prefs = _all;
			listener = searchHttpListenerFromSpecial (path, prefs);
			if (listener == null && pathSlash != path)
				listener = searchHttpListenerFromSpecial (pathSlash, prefs);

			return listener != null;
			}

		#endregion

		#region Public Methods

		public void AddPrefix (HttpListenerPrefix prefix, HttpListener listener)
			{
			List<HttpListenerPrefix> current, future;
			if (prefix.Host == "*")
				{
				do
					{
					current = _unhandled;
					future = current != null ? new List<HttpListenerPrefix> (current) : new List<HttpListenerPrefix> ();

					prefix.Listener = listener;
					addSpecial (future, prefix);
					}
				while (Interlocked.CompareExchange (ref _unhandled, future, current) != current);

				return;
				}

			if (prefix.Host == "+")
				{
				do
					{
					current = _all;
					future = current != null ? new List<HttpListenerPrefix> (current) : new List<HttpListenerPrefix> ();

					prefix.Listener = listener;
					addSpecial (future, prefix);
					}
				while (Interlocked.CompareExchange (ref _all, future, current) != current);

				return;
				}

			Dictionary<HttpListenerPrefix, HttpListener> prefs, prefs2;
			do
				{
				prefs = _prefixes;
				if (prefs.ContainsKey (prefix))
					{
					if (prefs[prefix] != listener)
						throw new HttpListenerException (87, String.Format ("There's another listener for {0}.", prefix));

					return;
					}

				prefs2 = new Dictionary<HttpListenerPrefix, HttpListener> (prefs);
				prefs2[prefix] = listener;
				}
			while (Interlocked.CompareExchange (ref _prefixes, prefs2, prefs) != prefs);
			}

		public void Close ()
			{
			_socket.Close ();

			HttpConnection[] conns = null;
			lock (_unregisteredSync)
				{
				if (_unregistered.Count == 0)
					return;

				var keys = _unregistered.Keys;
				conns = new HttpConnection[keys.Count];
				keys.CopyTo (conns, 0);
				_unregistered.Clear ();
				}

			for (var i = conns.Length - 1; i >= 0; i--)
				conns[i].Close (true);
			}

		public void RemovePrefix (HttpListenerPrefix prefix, HttpListener listener)
			{
			List<HttpListenerPrefix> current, future;
			if (prefix.Host == "*")
				{
				do
					{
					current = _unhandled;
					if (current == null)
						break;

					future = new List<HttpListenerPrefix> (current);
					if (!removeSpecial (future, prefix))
						break; // The prefix wasn't found.
					}
				while (Interlocked.CompareExchange (ref _unhandled, future, current) != current);

				leaveIfNoPrefix ();
				return;
				}

			if (prefix.Host == "+")
				{
				do
					{
					current = _all;
					if (current == null)
						break;

					future = new List<HttpListenerPrefix> (current);
					if (!removeSpecial (future, prefix))
						break; // The prefix wasn't found.
					}
				while (Interlocked.CompareExchange (ref _all, future, current) != current);

				leaveIfNoPrefix ();
				return;
				}

			Dictionary<HttpListenerPrefix, HttpListener> prefs, prefs2;
			do
				{
				prefs = _prefixes;
				if (!prefs.ContainsKey (prefix))
					break;

				prefs2 = new Dictionary<HttpListenerPrefix, HttpListener> (prefs);
				prefs2.Remove (prefix);
				}
			while (Interlocked.CompareExchange (ref _prefixes, prefs2, prefs) != prefs);

			leaveIfNoPrefix ();
			}

		#endregion
		}
	}