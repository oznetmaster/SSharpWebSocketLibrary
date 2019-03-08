#region License

/*
 * WebSocketServer.cs
 *
 * The MIT License
 *
 * Copyright (c) 2012-2015 sta.blockhead
 * Copyright © 2017 Nivloc Enterprises Ltd
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

#region Contributors

/*
 * Contributors:
 * - Juan Manuel Lallana <juan.manuel.lallana@gmail.com>
 * - Jonas Hovgaard <j@jhovgaard.dk>
 * - Liryna <liryna.stark@gmail.com>
 * - Rohan Singh <rohan-singh@hotmail.com>
 */

#endregion

using System;
using System.Collections.Generic;
#if SSHARP
using Crestron.SimplSharp;
using SSMono.Threading;
using TcpListener = Crestron.SimplSharp.CrestronSockets.CrestronListenerSocket;
using TcpClient = Crestron.SimplSharp.CrestronSockets.CrestronServerSocket;
using Activator = Crestron.SimplSharp.Reflection.ActivatorEx;
using SocketException = SSMono.Net.Sockets.SocketException;
using SSMono.Security.Principal;
using SSMono.Net;
using SSMono.Net.Sockets;
using SSMono.Web;
using HttpUtility = WebSocketSharp.Net.HttpUtility;
using NetworkCredential = WebSocketSharp.Net.NetworkCredential;
#else
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Security.Principal;
#endif
using System.Text;
using WebSocketSharp.Net;
using WebSocketSharp.Net.WebSockets;

namespace WebSocketSharp.Server
	{
	public class RecoverableSocketEventArgs : EventArgs
		{
		public SocketError SocketError;
		}

	/// <summary>
	/// Provides a WebSocket protocol server.
	/// </summary>
	/// <remarks>
	/// This class can provide multiple WebSocket services.
	/// </remarks>
	public class WebSocketServer
		{
		#region Private Fields

		private const int MAXIMUM_CONNECTIONS_DEFAULT = 16;

		private IPAddress _address;
		private bool _allowForwardedRequest;
		private AuthenticationSchemes _authSchemes;
		private static readonly string _defaultRealm;
		private bool _dnsStyle;
		private string _hostname;
		private TcpListener _listener;
		private Logger _log;
		private int _port;
		private string _realm;
		private string _realmInUse;
		private Thread _receiveThread;
		private bool _reuseAddress;
		private bool _secure;
		private WebSocketServiceManager _services;
#if !NETCF || BCC || SSL
		private ServerSslConfiguration _sslConfig;
		private ServerSslConfiguration _sslConfigInUse;
#endif
		private volatile ServerState _state;
		private object _sync;
		private Func<IIdentity, NetworkCredential> _userCredFinder;
		private int _maxConnections;

#if SSHARP
		private int _retryInterval = 1000;
#endif

		#endregion

#if SSHARP
		#region Public Events
		public delegate void RecoverableSocketeventHandler (object sender, RecoverableSocketEventArgs e);
		public event RecoverableSocketeventHandler RecoverableSocketEvent;
		#endregion
#endif

		#region Static Constructor

		static WebSocketServer ()
			{
			_defaultRealm = "SECRET AREA";
			}

		#endregion

		#region Public Constructors

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class.
		/// </summary>
		/// <remarks>
		/// The new instance listens for incoming handshake requests on
		/// <see cref="System.Net.IPAddress.Any"/> and port 80.
		/// </remarks>
		public WebSocketServer ()
			{
			var addr = IPAddress.Any;
			init (addr.ToString (), addr, 80, false
#if SSHARP
				, MAXIMUM_CONNECTIONS_DEFAULT
#endif
);
			}

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="port"/>.
		/// </summary>
		/// <remarks>
		///   <para>
		///   The new instance listens for incoming handshake requests on
		///   <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
		///   </para>
		///   <para>
		///   It provides secure connections if <paramref name="port"/> is 443.
		///   </para>
		/// </remarks>
		/// <param name="port">
		/// An <see cref="int"/> that represents the number of the port
		/// on which to listen.
		/// </param>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> is less than 1 or greater than 65535.
		/// </exception>
		public WebSocketServer (int port)
			: this (port, port == 443)
			{
			}

#if SSHARP
		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="port"/>.
		/// </summary>
		/// <remarks>
		///   <para>
		///   The new instance listens for incoming handshake requests on
		///   <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
		///   </para>
		///   <para>
		///   If <paramref name="port"/> is 443, that instance provides a secure connection.
		///   </para>
		/// </remarks>
		/// <param name="port">
		/// An <see cref="int"/> that represents the number of the port
		/// on which to listen.
		/// </param>
		/// <param name="maxConnections">
		/// An <see cref="int"/> that represents the maximum number of simultaneous connections.
		/// </param>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> isn't between 1 and 65535 inclusive.
		/// </exception>
		public WebSocketServer (int port, int maxConnections)
			: this (IPAddress.Any, port, port == 443, maxConnections)
			{
			}
#endif

#if SSHARP
		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="url"/>.
		/// </summary>
		/// <remarks>
		///   <para>
		///   The new instance listens for incoming handshake requests on
		///   the IP address of the host of <paramref name="url"/> and
		///   the port of <paramref name="url"/>.
		///   </para>
		///   <para>
		///   Either port 80 or 443 is used if <paramref name="url"/> includes
		///   no port. Port 443 is used if the scheme of <paramref name="url"/>
		///   is wss; otherwise, port 80 is used.
		///   </para>
		///   <para>
		///   The new instance provides secure connections if the scheme of
		///   <paramref name="url"/> is wss.
		///   </para>
		/// </remarks>
		/// <param name="url">
		/// A <see cref="string"/> that represents the WebSocket URL of the server.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="url"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="url"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="url"/> is invalid.
		///   </para>
		/// </exception>
		public WebSocketServer (string url)
			: this (url, MAXIMUM_CONNECTIONS_DEFAULT)
			{
			}
#endif

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="url"/>.
		/// </summary>
		/// <remarks>
		///   <para>
		///   The new instance listens for incoming handshake requests on
		///   the local IP address of the host of <paramref name="url"/> and
		///   the port of <paramref name="url"/>.
		///   </para>
		///   <para>
		///   Either port 80 or 443 is used if <paramref name="url"/> includes
		///   no port. Port 443 is used if the scheme of <paramref name="url"/>
		///   is wss; otherwise, port 80 is used.
		///   </para>
		///   <para>
		///   That instance provides secure connections if the scheme of
		///   <paramref name="url"/> is wss.
		///   </para>
		/// </remarks>
		/// <param name="url">
		/// A <see cref="string"/> that represents the WebSocket URL
		/// on which to listen.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="url"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="url"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="url"/> is invalid.
		///   </para>
		/// </exception>
		/// <param name="maxConnections">
		/// An <see cref="int"/> that represents the maximum number of simultaneous connections.
		/// </param>
		public WebSocketServer (
			string url
#if SSHARP
			, int maxConnections
#endif
			)
			{
			if (url == null)
				throw new ArgumentNullException ("url");

			if (url.Length == 0)
				throw new ArgumentException ("An empty string.", "url");

			Uri uri;
			string msg;
			if (!tryCreateUri (url, out uri, out msg))
				throw new ArgumentException (msg, "url");

			var host = uri.DnsSafeHost;

			var addr = host.ToIPAddress ();
			if (addr == null)
				{
				msg = "IThe host part could not be converted to an IP address.";
				throw new ArgumentException (msg, "url");
				}

			if (!addr.IsLocal ())
				{
				msg = "The IP address of the host is not a local IP address.";
				throw new ArgumentException (msg, "url");
				}

			init (host, addr, uri.Port, uri.Scheme == "wss"
#if SSHARP
				, maxConnections
#endif
				);
			}

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="port"/> and <paramref name="secure"/>.
		/// </summary>
		/// <remarks>
		/// The new instance listens for incoming handshake requests on
		/// <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
		/// </remarks>
		/// <param name="port">
		/// An <see cref="int"/> that represents the number of the port
		/// on which to listen.
		/// </param>
		/// <param name="secure">
		/// A <see cref="bool"/>: <c>true</c> if the new instance provides
		/// secure connections; otherwise, <c>false</c>.
		/// </param>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> is less than 1 or greater than 65535.
		/// </exception>
		public WebSocketServer (int port, bool secure)
			{
			if (!port.IsPortNumber ())
				{
				var msg = "Less than 1 or greater than 65535.";
				throw new ArgumentOutOfRangeException ("port", msg);
				}

			var addr = IPAddress.Any;
			init (addr.ToString (), addr, port, secure
#if SSHARP
				, MAXIMUM_CONNECTIONS_DEFAULT
#endif
				);
			}

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="address"/> and <paramref name="port"/>.
		/// </summary>
		/// <remarks>
		///   <para>
		///   The new instance listens for incoming handshake requests on
		///   <paramref name="address"/> and <paramref name="port"/>.
		///   </para>
		///   <para>
		///   It provides secure connections if <paramref name="port"/> is 443.
		///   </para>
		/// </remarks>
		/// <param name="address">
		/// A <see cref="System.Net.IPAddress"/> that represents the local IP address on which to listen.
		/// </param>
		/// <param name="port">
		/// An <see cref="int"/> that represents the number of the port
		/// on which to listen.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="address"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// <paramref name="address"/> is not a local IP address.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> is less than 1 or greater than 65535.
		/// </exception>
		public WebSocketServer (IPAddress address, int port)
			: this (address, port, port == 443
#if SSHARP
				, MAXIMUM_CONNECTIONS_DEFAULT
#endif
				)
			{
			}

#if SSHARP
		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="address"/>, <paramref name="port"/>, and <paramref name="secure"/>.
		/// </summary>
		/// <remarks>
		///   An instance initialized by this constructor listens for the incoming requests on
		///   <paramref name="address"/> and <paramref name="port"/>.
		/// </remarks>
		/// <param name="address">
		/// A <see cref="System.Net.IPAddress"/> that represents the local IP address of the server.
		/// </param>
		/// <param name="port">
		/// An <see cref="int"/> that represents the number of
		/// the port on which to listen.
		/// </param>
		/// <param name="secure">
		/// A <see cref="bool"/>: <c>true</c> if the new instance provides
		/// secure connections; otherwise, <c>false</c>.
		/// </param>
		/// <exception cref="ArgumentException">
		/// <paramref name="address"/> isn't a local IP address.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="address"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> isn't between 1 and 65535 inclusive.
		/// </exception>
		public WebSocketServer (IPAddress address, int port, bool secure)
			: this (address, port, secure, MAXIMUM_CONNECTIONS_DEFAULT)
			{
			}
#endif

		/// <summary>
		/// Initializes a new instance of the <see cref="WebSocketServer"/> class with the specified
		/// <paramref name="address"/>, <paramref name="port"/>, and <paramref name="secure"/>.
		/// </summary>
		/// <remarks>
		/// The new instance listens for the incoming handshake requests on
		/// <paramref name="address"/> and <paramref name="port"/>.
		/// </remarks>
		/// <param name="address">
		/// A <see cref="System.Net.IPAddress"/> that represents the local IP address for the server.
		/// </param>
		/// <param name="port">
		/// An <see cref="int"/> that represents the port number on which to listen.
		/// </param>
		/// <param name="secure">
		/// A <see cref="bool"/> that specifies providing secure connections or not.
		/// <c>true</c> specifies providing secure connections.
		/// </param>
#if SSHARP
		/// <param name="maxConnections">
		/// An <see cref="int"/> that represents the maximum number of simultaneous connections.
		/// </param>
#endif
		/// <exception cref="ArgumentNullException">
		/// <paramref name="address"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// <paramref name="address"/> is not a local IP address.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		/// <paramref name="port"/> is less than 1 or greater than 65535.
		/// </exception>
		public WebSocketServer (
			IPAddress address, int port, bool secure
#if SSHARP
			, int maxConnections
#endif
			)
			{
			if (address == null)
				throw new ArgumentNullException ("address");

			if (!address.IsLocal ())
				throw new ArgumentException ("Not a local IP address.", "address");

			if (!port.IsPortNumber ())
				{
				var msg = "Less than 1 or greater than 65535.";
				throw new ArgumentOutOfRangeException ("port", msg);
				}

			init (null, address, port, secure
#if SSHARP
				, maxConnections
#endif
				);
			}

		#endregion

		#region Public Properties

		/// <summary>
		/// Gets the IP address of the server.
		/// </summary>
		/// <value>
		/// A <see cref="System.Net.IPAddress"/> that represents the local
		/// IP address on which to listen for incoming handshake requests.
		/// </value>
		public IPAddress Address
			{
			get { return _address; }
			}

		/// <summary>
		/// Gets or sets a value indicating whether the server accepts every
		/// handshake request without checking the request URI.
		/// </summary>
		/// <remarks>
		/// The set operation does nothing if the server has already started or
		/// it is shutting down.
		/// </remarks>
		/// <value>
		///   <para>
		///   <c>true</c> if the server accepts every handshake request without
		///   checking the request URI; otherwise, <c>false</c>.
		///   </para>
		///   <para>
		///   The default value is <c>false</c>.
		///   </para>
		/// </value>
		public bool AllowForwardedRequest
			{
			get
				{
				return _allowForwardedRequest;
				}

			set
				{
				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_allowForwardedRequest = value;
					}
				}
			}

		/// <summary>
		/// Gets or sets the scheme used to authenticate the clients.
		/// </summary>
		/// <remarks>
		/// The set operation does nothing if the server has already started or
		/// it is shutting down.
		/// </remarks>
		/// <value>
		///   <para>
		///   One of the <see cref="WebSocketSharp.Net.AuthenticationSchemes"/>
		///   enum values.
		///   </para>
		///   <para>
		///   It represents the scheme used to authenticate the clients.
		///   </para>
		///   <para>
		///   The default value is
		///   <see cref="WebSocketSharp.Net.AuthenticationSchemes.Anonymous"/>.
		///   </para>
		/// </value>
		public AuthenticationSchemes AuthenticationSchemes
			{
			get { return _authSchemes; }

			set
				{
				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_authSchemes = value;
					}
				}
			}

		/// <summary>
		/// Gets a value indicating whether the server has started.
		/// </summary>
		/// <value>
		/// <c>true</c> if the server has started; otherwise, <c>false</c>.
		/// </value>
		public bool IsListening
			{
			get { return _state == ServerState.Start; }
			}

		/// <summary>
		/// Gets a value indicating whether secure connections are provided.
		/// </summary>
		/// <value>
		/// <c>true</c> if this instance provides secure connections; otherwise,
		/// <c>false</c>.
		/// </value>
		public bool IsSecure
			{
			get { return _secure; }
			}

		/// <summary>
		/// Gets or sets a value indicating whether the server cleans up the inactive sessions
		/// periodically.
		/// </summary>
		/// <remarks>
		/// The set operation does nothing if the server has already started or
		/// it is shutting down.
		/// </remarks>
		/// <value>
		///   <para>
		///   <c>true</c> if the server cleans up the inactive sessions
		///   every 60 seconds; otherwise, <c>false</c>.
		///   </para>
		///   <para>
		///   The default value is <c>true</c>.
		///   </para>
		/// </value>
		public bool KeepClean
			{
			get { return _services.KeepClean; }

			set
				{
				_services.KeepClean = value;
				}
			}

		/// <summary>
		/// Gets the logging function for the server.
		/// </summary>
		/// <remarks>
		/// The default logging level is <see cref="LogLevel.Error"/>.
		/// </remarks>
		/// <value>
		/// A <see cref="Logger"/> that provides the logging function.
		/// </value>
		public Logger Log
			{
			get { return _log; }
			}

		/// <summary>
		/// Gets the port of the server.
		/// </summary>
		/// <value>
		/// An <see cref="int"/> that represents the number of the port
		/// on which to listen for incoming handshake requests.
		/// </value>
		public int Port
			{
			get { return _port; }
			}

		/// <summary>
		/// Gets or sets the realm used for authentication.
		/// </summary>
		/// <remarks>
		///   <para>
		///   "SECRET AREA" is used as the realm if the value is
		///   <see langword="null"/> or an empty string.
		///   </para>
		///   <para>
		///   The set operation does nothing if the server has
		///   already started or it is shutting down.
		///   </para>
		/// </remarks>
		/// <value>
		///   <para>
		///   A <see cref="string"/> or <see langword="null"/> by default.
		///   </para>
		///   <para>
		///   That string represents the name of the realm.
		///   </para>
		/// </value>
		public string Realm
			{
			get { return _realm; }

			set
				{
				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_realm = value;
					}
				}
			}

#if SSHARP
		public int RetryInterval
			{
			get { return _retryInterval; }
			set
				{
				if (value < 0)
					throw new ArgumentOutOfRangeException ("value", "must be >= 0");

				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_retryInterval = value;
					}
				}
			}
#endif

		/// <summary>
		/// Gets or sets a value indicating whether the server is allowed to
		/// be bound to an address that is already in use.
		/// </summary>
		/// <remarks>
		///   <para>
		///   You should set this property to <c>true</c> if you would
		///   like to resolve to wait for socket in TIME_WAIT state.
		///   </para>
		///   <para>
		///   The set operation does nothing if the server has already started or
		///   it is shutting down.
		///   </para>
		/// </remarks>
		/// <value>
		///   <para>
		///   <c>true</c> if the server is allowed to be bound to an address
		///   that is already in use; otherwise, <c>false</c>.
		///   </para>
		///   <para>
		///   The default value is <c>false</c>.
		///   </para>
		/// </value>
		public bool ReuseAddress
			{
			get { return _reuseAddress; }

			set
				{
				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_reuseAddress = value;
					}
				}
			}

#if !NETCF || BCC || SSL
		/// <summary>
		/// Gets the configuration for secure connection.
		/// </summary>
		/// <remarks>
		/// This configuration will be referenced when attempts to start,
		/// so it must be configured before the start method is called.
		/// </remarks>
		/// <value>
		/// A <see cref="ServerSslConfiguration"/> that represents
		/// the configuration used to provide secure connections.
		/// </value>
		/// <exception cref="InvalidOperationException">
		/// This instance does not provide secure connections.
		/// </exception>
		public ServerSslConfiguration SslConfiguration
			{
			get
				{
				if (!_secure)
					{
					var msg = "This instance does not provide secure connections.";
					throw new InvalidOperationException (msg);
					}

				return getSslConfiguration ();
				}
			}
#endif

		/// <summary>
		/// Gets or sets the delegate used to find the credentials for an identity.
		/// </summary>
		/// <remarks>
		///   <para>
		///   No credentials are found if the method invoked by
		///   the delegate returns <see langword="null"/> or
		///   the value is <see langword="null"/>.
		///   </para>
		///   <para>
		///   The set operation does nothing if the server has already
		///   started or it is shutting down.
		///   </para>
		/// </remarks>
		/// <value>
		///   <para>
		///   A <c>Func&lt;<see cref="IIdentity"/>,
		///   <see cref="NetworkCredential"/>&gt;</c> delegate or
		///   <see langword="null"/> if not needed.
		///   </para>
		///   <para>
		///   That delegate invokes the method called for finding
		///   the credentials used to authenticate a client.
		///   </para>
		///   <para>
		///   The default value is <see langword="null"/>.
		///   </para>
		/// </value>
		public Func<IIdentity, NetworkCredential> UserCredentialsFinder
			{
			get { return _userCredFinder; }

			set
				{
				string msg;
				if (!canSet (out msg))
					{
					_log.Warn (msg);
					return;
					}

				lock (_sync)
					{
					if (!canSet (out msg))
						{
						_log.Warn (msg);
						return;
						}

					_userCredFinder = value;
					}
				}
			}

		/// <summary>
		/// Gets or sets the time to wait for the response to the WebSocket Ping or
		/// Close.
		/// </summary>
		/// <remarks>
		/// The set operation does nothing if the server has already started or
		/// it is shutting down.
		/// </remarks>
		/// <value>
		///   <para>
		///   A <see cref="TimeSpan"/> to wait for the response.
		///   </para>
		///   <para>
		///   The default value is the same as 1 second.
		///   </para>
		/// </value>
		/// <exception cref="ArgumentOutOfRangeException">
		/// The value specified for a set operation is zero or less.
		/// </exception>
		public TimeSpan WaitTime
			{
			get { return _services.WaitTime; }

			set
				{
				_services.WaitTime = value;
				}
			}

		/// <summary>
		/// A <see cref="WebSocketServiceManager"/> that manages
		/// the WebSocket services provided by the server.
		/// </summary>
		/// <value>
		/// A <see cref="WebSocketServiceManager"/> that manages the WebSocket services.
		/// </value>
		public WebSocketServiceManager WebSocketServices
			{
			get { return _services; }
			}

		#endregion

		#region Private Methods

		private void abort ()
			{
			lock (_sync)
				{
				if (_state != ServerState.Start)
					return;

				_state = ServerState.ShuttingDown;
				}

			try
				{
				try
					{
					_listener.Stop ();
					}
				finally
					{
					_services.Stop (1006, String.Empty);
					}
				}
			catch
				{
				}

			_state = ServerState.Stop;
			}

		private bool authenticateClient (TcpListenerWebSocketContext context)
			{
			if (_authSchemes == AuthenticationSchemes.Anonymous)
				return true;

			if (_authSchemes == AuthenticationSchemes.None)
				return false;

			return context.Authenticate (_authSchemes, _realmInUse, _userCredFinder);
			}

		private bool canSet (out string message)
			{
			message = null;

			if (_state == ServerState.Start)
				{
				message = "The server has already started.";
				return false;
				}

			if (_state == ServerState.ShuttingDown)
				{
				message = "The server is shutting down.";
				return false;
				}

			return true;
			}

		private bool checkHostNameForRequest (string name)
			{
			return !_dnsStyle || Uri.CheckHostName (name) != UriHostNameType.Dns || name == _hostname;
			}

#if !NETCF || BCC || SSL
		private static bool checkSslConfiguration (ServerSslConfiguration configuration, out string message)
			{
			message = null;

			if (configuration.ServerCertificate == null)
				{
				message = "There is no server certificate for secure connection.";
				return false;
				}

			return true;
			}
#endif

		private string getRealm ()
			{
			var realm = _realm;
			return realm != null && realm.Length > 0 ? realm : _defaultRealm;
			}

#if !NETCF || BCC || SSL
		private ServerSslConfiguration getSslConfiguration ()
			{
			if (_sslConfig == null)
				_sslConfig = new ServerSslConfiguration ();

			return _sslConfig;
			}
#endif

		private void init (
			string hostname, IPAddress address, int port, bool secure
#if SSHARP
			, int maxConnections
#endif
			)
			{
			_hostname = hostname;
			_address = address;
			_port = port;
			_secure = secure;
			_maxConnections = maxConnections;

			_authSchemes = AuthenticationSchemes.Anonymous;
			_dnsStyle = Uri.CheckHostName (hostname) == UriHostNameType.Dns;
			_listener = new TcpListener (_address, _port
#if SSHARP
				, _maxConnections
#endif
				);
			_log = new Logger ();
			_services = new WebSocketServiceManager (_log);
			_sync = new object ();
			}

		private void processRequest (TcpListenerWebSocketContext context)
			{
			if (!authenticateClient (context))
				{
				context.Close (HttpStatusCode.Forbidden);
				return;
				}

			var uri = context.RequestUri;
			if (uri == null)
				{
				context.Close (HttpStatusCode.BadRequest);
				return;
				}

			if (!_allowForwardedRequest)
				{
				if (uri.Port != _port)
					{
					context.Close (HttpStatusCode.BadRequest);
					return;
					}

				if (!checkHostNameForRequest (uri.DnsSafeHost))
					{
					context.Close (HttpStatusCode.NotFound);
					return;
					}
				}

			var path = uri.AbsolutePath;
			if (path.IndexOfAny (new[] { '%', '+' }) > -1)
				path = HttpUtility.UrlDecode (path, Encoding.UTF8);

			WebSocketServiceHost host;
			if (!_services.InternalTryGetServiceHost (path, out host))
				{
				context.Close (HttpStatusCode.NotImplemented);
				return;
				}

			host.StartSession (context);
			}

		private void receiveRequest ()
			{
			while (true)
				{
				TcpClient cl = null;

				try
					{
					cl = _listener.AcceptTcpClient ();

					ThreadPool.QueueUserWorkItem (state =>
						{
						try
							{
							var ctx = new TcpListenerWebSocketContext (cl, null, _secure,
#if !NETCF || BCC || SSL
								_sslConfigInUse,
#endif
								_log);

							processRequest (ctx);
							}
						catch (Exception ex)
							{
							_log.Error (ex.Message);
							_log.Debug (ex.ToString ());

							cl.Close ();
							}
						});
					}
				catch (SocketException ex)
					{
					if (_state == ServerState.ShuttingDown)
						{
						_log.Info ("The underlying listener is stopped.");
						break;
						}

#if SSHARP
					if (ex.SocketErrorCode == SocketError.TooManyOpenSockets || ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
						{
						_log.Warn (ex.Message);
						_log.Debug (ex.ToString ());

						if (RecoverableSocketEvent != null)
							RecoverableSocketEvent (this, new RecoverableSocketEventArgs { SocketError = ex.SocketErrorCode });

						Thread.Sleep (_retryInterval);

						continue;
						}
#endif

					_log.Fatal (ex.Message);
					_log.Debug (ex.ToString ());

					break;
					}
				catch (Exception ex)
					{
					_log.Fatal (ex.Message);
					_log.Debug (ex.ToString ());

					if (cl != null)
						cl.Close ();

					break;
					}
				}

			if (_state != ServerState.ShuttingDown)
				abort ();
			}

		private void start (ServerSslConfiguration sslConfig)
			{
			if (_state == ServerState.Start)
				{
				_log.Info ("The server has already started.");
				return;
				}

			if (_state == ServerState.ShuttingDown)
				{
				_log.Warn ("The server is shutting down.");
				return;
				}

			lock (_sync)
				{
				if (_state == ServerState.Start)
					{
					_log.Info ("The server has already started.");
					return;
					}

				if (_state == ServerState.ShuttingDown)
					{
					_log.Warn ("The server is shutting down.");
					return;
					}


#if !NETCF || BCC || SSL
				_sslConfigInUse = sslConfig;
#endif
				_realmInUse = getRealm ();

				_services.Start ();
				try
					{
					startReceiving ();
					}
				catch
					{
					_services.Stop (1011, String.Empty);
					throw;
					}

				_state = ServerState.Start;
				}
			}

		private void startReceiving ()
			{
#if !SSHARP
			if (_reuseAddress)
				_listener.Server.SetSocketOption (
				  SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
#endif
			try
				{
				_listener.Start ();
				}
			catch (Exception ex)
				{
				var msg = "The underlying listener has failed to start.";
				throw new InvalidOperationException (msg, ex);
				}

			_receiveThread = new Thread (new ThreadStart (receiveRequest));
#if !NETCF
			_receiveThread.IsBackground = true;
#endif
			_receiveThread.Start ();
			}

		private void stop (ushort code, string reason)
			{
			if (_state == ServerState.Ready)
				{
				_log.Info ("The server is not started.");
				return;
				}

			if (_state == ServerState.ShuttingDown)
				{
				_log.Info ("The server is shutting down.");
				return;
				}

			if (_state == ServerState.Stop)
				{
				_log.Info ("The server has already stopped.");
				return;
				}

			lock (_sync)
				{
				if (_state == ServerState.ShuttingDown)
					{
					_log.Info ("The server is shutting down.");
					return;
					}

				if (_state == ServerState.Stop)
					{
					_log.Info ("The server has already stopped.");
					return;
					}

				_state = ServerState.ShuttingDown;
				}

			try
				{
				var threw = false;
				try
					{
					stopReceiving (5000);
					}
				catch
					{
					threw = true;
					throw;
					}
				finally
					{
					try
						{
						_services.Stop (code, reason);
						}
					catch
						{
						if (!threw)
							throw;
						}
					}
				}
			finally
				{
				_state = ServerState.Stop;
				}
			}

		private void stopReceiving (int millisecondsTimeout)
			{
			try
				{
				_listener.Stop ();
				}
			catch (Exception ex)
				{
				var msg = "The underlying listener has failed to stop.";
				throw new InvalidOperationException (msg, ex);
				}

			_receiveThread.Join (millisecondsTimeout);
			}

		private static bool tryCreateUri (string uriString, out Uri result, out string message)
			{
			if (!uriString.TryCreateWebSocketUri (out result, out message))
				return false;

			if (result.PathAndQuery != "/")
				{
				result = null;
				message = "It includes either or both path and query components.";

				return false;
				}

			return true;
			}

		#endregion

		#region Public Methods

		/// <summary>
		/// Adds a WebSocket service with the specified behavior, path,
		/// and delegate.
		/// </summary>
		/// <param name="path">
		///   <para>
		///   A <see cref="string"/> that represents an absolute path to
		///   the service to add.
		///   </para>
		///   <para>
		///   / is trimmed from the end of the string if present.
		///   </para>
		/// </param>
		/// <param name="creator">
		///   <para>
		///   A <c>Func&lt;TBehavior&gt;</c> delegate.
		///   </para>
		///   <para>
		///   It invokes the method called when creating a new session
		///   instance for the service.
		///   </para>
		///   <para>
		///   The method must create a new instance of
		///   the specified behavior class and return it.
		///   </para>
		/// </param>
		/// <typeparam name="TBehavior">
		///   <para>
		///   The type of the behavior for the service.
		///   </para>
		///   <para>
		///   It must inherit the <see cref="WebSocketBehavior"/> class.
		///   </para>
		/// </typeparam>
		/// <exception cref="ArgumentNullException">
		///   <para>
		///   <paramref name="path"/> is <see langword="null"/>.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="creator"/> is <see langword="null"/>.
		///   </para>
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="path"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is not an absolute path.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> includes either or both
		///   query and fragment components.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is already in use.
		///   </para>
		/// </exception>
		[Obsolete ("This method will be removed. Use added one instead.")]
		public void AddWebSocketService<TBehavior> (string path, Func<TBehavior> creator) where TBehavior : WebSocketBehavior
			{
			if (path == null)
				throw new ArgumentNullException ("path");

			if (creator == null)
				throw new ArgumentNullException ("initializer");

			if (path.Length == 0)
				throw new ArgumentException ("An empty string.", "path");

			if (path[0] != '/')
				throw new ArgumentException ("Not an absolute path.", "path");

			if (path.IndexOfAny (new[] { '?', '#' }) > -1)
				{
				var msg = "It includes either or both query and fragment components.";
				throw new ArgumentException (msg, "path");
				}

			_services.Add<TBehavior> (path, creator);
			}

		/// <summary>
		/// Adds a WebSocket service with the specified behavior and path.
		/// </summary>
		/// <param name="path">
		///   <para>
		///   A <see cref="string"/> that represents an absolute path to
		///   the service to add.
		///   </para>
		///   <para>
		///   / is trimmed from the end of the string if present.
		///   </para>
		/// </param>
		/// <typeparam name="TBehaviorWithNew">
		///   <para>
		///   The type of the behavior for the service.
		///   </para>
		///   <para>
		///   It must inherit the <see cref="WebSocketBehavior"/> class.
		///   </para>
		///   <para>
		///   And also, it must have a public parameterless constructor.
		///   </para>
		/// </typeparam>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="path"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="path"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is not an absolute path.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> includes either or both
		///   query and fragment components.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is already in use.
		///   </para>
		/// </exception>
		public void AddWebSocketService<TBehaviorWithNew> (string path) where TBehaviorWithNew : WebSocketBehavior, new ()
			{
			_services.AddService<TBehaviorWithNew> (path, null);
			}

		/// <summary>
		/// Adds a WebSocket service with the specified behavior, path,
		/// and delegate.
		/// </summary>
		/// <param name="path">
		///   <para>
		///   A <see cref="string"/> that represents an absolute path to
		///   the service to add.
		///   </para>
		///   <para>
		///   / is trimmed from the end of the string if present.
		///   </para>
		/// </param>
		/// <param name="initializer">
		///   <para>
		///   An <c>Action&lt;TBehaviorWithNew&gt;</c> delegate or
		///   <see langword="null"/> if not needed.
		///   </para>
		///   <para>
		///   The delegate invokes the method called when initializing
		///   a new session instance for the service.
		///   </para>
		/// </param>
		/// <typeparam name="TBehaviorWithNew">
		///   <para>
		///   The type of the behavior for the service.
		///   </para>
		///   <para>
		///   It must inherit the <see cref="WebSocketBehavior"/> class.
		///   </para>
		///   <para>
		///   And also, it must have a public parameterless constructor.
		///   </para>
		/// </typeparam>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="path"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="path"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is not an absolute path.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> includes either or both
		///   query and fragment components.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is already in use.
		///   </para>
		/// </exception>
		public void AddWebSocketService<TBehaviorWithNew> (
		  string path, Action<TBehaviorWithNew> initializer
		)
		  where TBehaviorWithNew : WebSocketBehavior, new ()
			{
			_services.AddService<TBehaviorWithNew> (path, initializer);
			}

		/// <summary>
		/// Removes a WebSocket service with the specified path.
		/// </summary>
		/// <remarks>
		/// The service is stopped with close status 1001 (going away)
		/// if it has already started.
		/// </remarks>
		/// <returns>
		/// <c>true</c> if the service is successfully found and removed;
		/// otherwise, <c>false</c>.
		/// </returns>
		/// <param name="path">
		///   <para>
		///   A <see cref="string"/> that represents an absolute path to
		///   the service to remove.
		///   </para>
		///   <para>
		///   / is trimmed from the end of the string if present.
		///   </para>
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// <paramref name="path"/> is <see langword="null"/>.
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="path"/> is an empty string.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> is not an absolute path.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="path"/> includes either or both
		///   query and fragment components.
		///   </para>
		/// </exception>
		public bool RemoveWebSocketService (string path)
			{
			return _services.RemoveService (path);
			}

		/// <summary>
		/// Starts receiving incoming handshake requests.
		/// </summary>
		/// <remarks>
		/// This method does nothing if the server has already started or
		/// it is shutting down.
		/// </remarks>
		/// <exception cref="InvalidOperationException">
		///   <para>
		///   There is no server certificate for secure connection.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   The underlying <see cref="TcpListener"/> has failed to start.
		///   </para>
		/// </exception>
		public void Start ()
			{
			ServerSslConfiguration sslConfig = null;

			if (_secure)
				{
				sslConfig = new ServerSslConfiguration (getSslConfiguration ());

				string msg;
				if (!checkSslConfiguration (sslConfig, out msg))
					throw new InvalidOperationException (msg);
				}

			start (sslConfig);
			}

		/// <summary>
		/// Stops receiving incoming handshake requests.
		/// </summary>
		/// <exception cref="InvalidOperationException">
		/// The underlying <see cref="TcpListener"/> has failed to stop.
		/// </exception>
		public void Stop ()
			{
			stop (1001, String.Empty);
			}

		/// <summary>
		/// Stops receiving incoming handshake requests and closes each connection
		/// with the specified code and reason.
		/// </summary>
		/// <param name="code">
		///   <para>
		///   A <see cref="ushort"/> that represents the status code
		///   indicating the reason for the close.
		///   </para>
		///   <para>
		///   The status codes are defined in
		///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
		///   Section 7.4</see> of RFC 6455.
		///   </para>
		/// </param>
		/// <param name="reason">
		///   <para>
		///   A <see cref="string"/> that represents the reason for the close.
		///   </para>
		///   <para>
		///   The size must be 123 bytes or less in UTF-8.
		///   </para>
		/// </param>
		/// <exception cref="ArgumentOutOfRangeException">
		///   <para>
		///   <paramref name="code"/> is less than 1000 or greater than 4999.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   The size of <paramref name="reason"/> is greater than 123 bytes.
		///   </para>
		/// </exception>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="code"/> is 1010 (mandatory extension).
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="code"/> is 1005 (no status) and there is reason.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="reason"/> could not be UTF-8-encoded.
		///   </para>
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// The underlying <see cref="TcpListener"/> has failed to stop.
		/// </exception>
		[Obsolete ("This method will be removed.")]
		public void Stop (ushort code, string reason)
			{
			if (!code.IsCloseStatusCode ())
				{
				var msg = "Less than 1000 or greater than 4999.";
				throw new ArgumentOutOfRangeException ("code", msg);
				}

			if (code == 1010)
				{
				var msg = "1010 cannot be used.";
				throw new ArgumentException (msg, "code");
				}

			if (!reason.IsNullOrEmpty ())
				{
				if (code == 1005)
					{
					var msg = "1005 cannot be used.";
					throw new ArgumentException (msg, "code");
					}

				byte[] bytes;
				if (!reason.TryGetUTF8EncodedBytes (out bytes))
					{
					var msg = "It could not be UTF-8-encoded.";
					throw new ArgumentException (msg, "reason");
					}

				if (bytes.Length > 123)
					{
					var msg = "Its size is greater than 123 bytes.";
					throw new ArgumentOutOfRangeException ("reason", msg);
					}
				}

			stop (code, reason);
			}

		/// <summary>
		/// Stops receiving incoming handshake requests and closes each connection
		/// with the specified code and reason.
		/// </summary>
		/// <param name="code">
		///   <para>
		///   One of the <see cref="CloseStatusCode"/> enum values.
		///   </para>
		///   <para>
		///   It represents the status code indicating the reason for the close.
		///   </para>
		/// </param>
		/// <param name="reason">
		///   <para>
		///   A <see cref="string"/> that represents the reason for the close.
		///   </para>
		///   <para>
		///   The size must be 123 bytes or less in UTF-8.
		///   </para>
		/// </param>
		/// <exception cref="ArgumentException">
		///   <para>
		///   <paramref name="code"/> is
		///   <see cref="CloseStatusCode.MandatoryExtension"/>.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="code"/> is   
		///	<see cref="CloseStatusCode.NoStatus"/> and there is reason.
		///   </para>
		///   <para>
		///   -or-
		///   </para>
		///   <para>
		///   <paramref name="reason"/> could not be UTF-8-encoded.
		///   </para>
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		/// The size of <paramref name="reason"/> is greater than 123 bytes.
		/// </exception>
		/// <exception cref="InvalidOperationException">
		/// The underlying <see cref="TcpListener"/> has failed to stop.
		/// </exception>
		[Obsolete ("This method will be removed.")]
		public void Stop (CloseStatusCode code, string reason)
			{
			if (code == CloseStatusCode.MandatoryExtension)
				{
				var msg = "MandatoryExtension cannot be used.";
				throw new ArgumentException (msg, "code");
				}

			if (!reason.IsNullOrEmpty ())
				{
				if (code == CloseStatusCode.NoStatus)
					{
					var msg = "NoStatus cannot be used.";
					throw new ArgumentException (msg, "code");
					}

				byte[] bytes;
				if (!reason.TryGetUTF8EncodedBytes (out bytes))
					{
					var msg = "It could not be UTF-8-encoded.";
					throw new ArgumentException (msg, "reason");
					}

				if (bytes.Length > 123)
					{
					var msg = "Its size is greater than 123 bytes.";
					throw new ArgumentOutOfRangeException ("reason", msg);
					}
				}

			stop ((ushort)code, reason);
			}

		#endregion
		}
	}
