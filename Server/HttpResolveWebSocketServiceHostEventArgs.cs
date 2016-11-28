#region License
/*
 * HttpRequestEventArgs.cs
 *
 * The MIT License
 *
 * Copyright (c) 2012-2014 sta.blockhead
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

using System;
using System.ComponentModel;
using WebSocketSharp.Net;

namespace WebSocketSharp.Server
	{
	/// <summary>
	/// Contains the event data associated with an HTTP request event that
	/// the <see cref="HttpServer"/> emits.
	/// </summary>
	/// <remarks>
	///   <para>
	///   An HTTP request event occurs when the <see cref="HttpServer"/> receives an HTTP request.
	///   </para>
	///   <para>
	///   If you would like to get the request data, you should access
	///   the <see cref="HttpRequestEventArgs.Request"/> property.
	///   </para>
	///   <para>
	///   And if you would like to get the data used to return a response, you should access
	///   the <see cref="HttpRequestEventArgs.Response"/> property.
	///   </para>
	/// </remarks>
	public class HttpResolveWebSocketServiceHostEventArgs : EventArgs
		{
		#region Private Fields

		private string _path;

		#endregion

		#region Internal Constructors

		internal HttpResolveWebSocketServiceHostEventArgs (string path)
			{
			_path = path;
			}

		#endregion

		#region Public Properties

		/// <summary>
		/// Gets the <see cref="String"/> that contains the path of the websocket service
		/// </summary>
		/// <value>
		/// A <see cref="String"/> that contains the path of the websocket service.
		/// </value>
		public string Path
			{
			get
				{
				return _path;
				}
			}

		/// <summary>
		/// Gets the <see cref="WebSocketServiceHost"/> websocket service host returned by the event handler.
		/// </summary>
		/// <value>
		/// A <see cref="WebSocketServiceHost"/> used to return a response.
		/// </value>
		public WebSocketServiceHost Host
			{
			get;
			set;
			}

		#endregion
		}
	}
