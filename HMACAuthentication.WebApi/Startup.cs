using System;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(HMACAuthentication.WebApi.Startup))]

namespace HMACAuthentication.WebApi
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //var config = new HttpConfiguration();

            //WebApiConfig.Register(config);

     
        }
    }
}
