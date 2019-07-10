using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;
using SSMono.Net;

namespace WebSocketSharp.Net
	{
	public static class CookieExtensions
		{
		internal static bool EqualsWithoutValue (this Cookie thisCookie, Cookie cookie)
			{
			var caseSensitive = StringComparison.InvariantCulture;
			var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

			return thisCookie.Name.Equals (cookie.Name, caseInsensitive)
					 && thisCookie.Path.Equals (cookie.Path, caseSensitive)
					 && thisCookie.Domain.Equals (cookie.Domain, caseInsensitive)
					 && thisCookie.Version == cookie.Version;
			}

		}
	}