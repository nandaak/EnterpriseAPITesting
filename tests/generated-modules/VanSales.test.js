/**
 * Auto-generated test for module: VanSales
 * Generated: 2025-12-01T13:40:51.245Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: No
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'VanSales';

describe('Module: VanSales', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new VanSales', async () => {
    const [url, payload] = ["/erp-apis/VanSales/AddReturnSalesInvoice",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","returnInvoiceDate":"2025-11-26T16:29:05.638Z","salesInvoiceHeaderId":"00000000-0000-0000-0000-000000000000","description":"string","warehouseId":1,"warehouseName":"string","posSessionId":"00000000-0000-0000-0000-000000000000","returnSalesInvoiceDetails":[{"toReturnQuantity":1,"salesInvoiceDetailId":"00000000-0000-0000-0000-000000000000","returnSalesInvoiceDetailIngredients":[{}]}],"posReturnInvoicePayments":[{"amount":1,"paymentMethodType":{},"paymentMethodCode":"string","paymentMethodId":1}]}];
    
    logger.info('Testing CREATE for VanSales');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created VanSales with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get VanSales by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VanSales/GetSalesInvoiceByCustomerId",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for VanSales with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read VanSales');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update VanSales', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/VanSales/EditCustomerCategory",{"id":"<createdId>","name":"string","nameAr":"string","categoryId":"<createdId>","marketType":"B2B","birthdate":"2025-11-26T16:29:05.638Z","photo":"string","tagIds":[1],"contactInfo":{"contactPhone":"string","contactEmail":"string","contactMobileCode":"string","contactMobile":"string","contactWebsite":"string","contactFax":"string","contactPersonPhone":"string","contactPersonMobileCode":"string","contactPersonMobile":"string","contactPersonEmail":"string","contactPersonName":"string"},"financialInfo":{"paymentTermId":"<createdId>","pricePolicyId":"<createdId>","allowCreditLimit":true,"creditLimit":1,"currencyId":"<createdId>"},"legalInfo":{"commercialRegistrationNumber":"string","taxIdentificationNumber":"string","street":"string","citySubdivisionName":"string","cityName":"string","postalZone":"string","countrySubEntity":"string","countryId":"<createdId>","buildingNumber":"string","additionalStreetName":"string","registrationName":"string","otherID":"<createdId>","nationalNumber":"string"},"accountingInfo":{"receivableAccountId":"<createdId>","salesAccountId":"<createdId>","salesReturnAccountId":"<createdId>","discountAccountId":"<createdId>"},"customerAddresses":[{"id":"<createdId>","longitude":1,"latitude":1,"errorRadius":1}],"customerMarketPlaces":[{"id":"<createdId>","externalIdentifier":"00000000-0000-0000-0000-000000000000","marketPlaceId":"<createdId>","salesManId":"<createdId>","address":"string"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for VanSales with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated VanSales');
  }, TEST_TIMEOUT);
  
  
});
