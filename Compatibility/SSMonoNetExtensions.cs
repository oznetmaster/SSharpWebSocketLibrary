using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Crestron.SimplSharp;

namespace SSMono.Net
	{
	public static class SSMonoNetExtensions
		{
		public static int getMaxAge (this SSMono.Net.Cookie cookie)
				{
				if (cookie.Expires == DateTime.MinValue)
					return 0;

				var expires = cookie.Expires.Kind != DateTimeKind.Local
							  ? cookie.Expires.ToLocalTime ()
							  : cookie.Expires;

				var span = expires - DateTime.Now;
				return span > TimeSpan.Zero
					   ? (int)span.TotalSeconds
					   : 0;
				}

		public static void setMaxAge (this SSMono.Net.Cookie cookie, int value)
			{
			cookie.Expires = value > 0
						 ? DateTime.Now.AddSeconds ((double)value)
						 : DateTime.Now;
			}
		}
	}