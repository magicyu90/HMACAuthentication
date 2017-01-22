using HMACAuthentication.WebApi.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace HMACAuthentication.WebApi.Controllers
{
    [RoutePrefix("api/orders")]
    [HmacAuthentication]
    public class OrdersController : ApiController
    {
        [Route("")]
        public IHttpActionResult Get()
        {
            ClaimsPrincipal principal = Request.GetRequestContext().Principal as ClaimsPrincipal;

            var userName = ClaimsPrincipal.Current.Identity.Name;

            return Ok(Order.CreateOrders());

        }

        [Route("")]
        public IHttpActionResult Post(Order order)
        {
            return Ok(order);
        }
    }

    public class Order
    {
        public int OrderId { get; set; }
        public string CustomerName { get; set; }

        public Boolean IsShipped { get; set; }

        public string ShipperCity { get; set; }

        public static List<Order> CreateOrders()
        {
            return new List<Order>
            {
                new Order {  OrderId = 10248, CustomerName = "Taiseer Joudeh", ShipperCity = "Amman", IsShipped = true },
                new Order {OrderId = 10249, CustomerName = "Ahmad Hasan", ShipperCity = "Dubai", IsShipped = false},
                new Order {OrderId = 10250,CustomerName = "Tamer Yaser", ShipperCity = "Jeddah", IsShipped = false },
                new Order {OrderId = 10251,CustomerName = "Lina Majed", ShipperCity = "Abu Dhabi", IsShipped = false},
                new Order {OrderId = 10252,CustomerName = "Yasmeen Rami", ShipperCity = "Kuwait", IsShipped = true}
            };
        }
    }
}
