// config/endpoint-config.js
module.exports = {
  endpointConfigs: {
    // Sales endpoints
    "Sales.Transaction.Return_Sales_Invoice": {
      methods: {
        Post: { method: "POST", expectsId: true },
        PUT: { method: "PUT", expectsId: true },
        DELETE: { method: "DELETE", expectsId: true },
        View: { method: "GET", expectsId: true },
      },
    },
    "Sales.Transaction.Project_Invoice": {
      methods: {
        Post: { method: "POST", expectsId: true },
        PUT: { method: "PUT", expectsId: true },
        DELETE: { method: "DELETE", expectsId: true },
      },
    },
    // Purchase endpoints
    "Purchase.Master_Data.Vendor_Category": {
      methods: {
        Post: { method: "POST", expectsId: true },
        PUT: { method: "PUT", expectsId: true },
        DELETE: { method: "DELETE", expectsId: true },
        EDIT: { method: "GET", expectsId: true },
      },
    },
    // Add more endpoint configurations as needed
  },

  getEndpointConfig(modulePath, methodType) {
    const config = this.endpointConfigs[modulePath];
    return config ? config.methods[methodType] : null;
  },

  shouldSkipTest(moduleConfig, methodType) {
    const endpoint = moduleConfig[methodType];
    return !endpoint || endpoint[0] === "URL_HERE" || endpoint[0] === "";
  },
};
