/**
 * Auto-generated test for module: Customer
 * Generated: 2025-12-01T13:40:51.232Z
 * 
 * Operations available:
 * - POST: Yes
 * - GET: Yes
 * - PUT: Yes
 * - DELETE: Yes
 */

const EnhancedSchemaAdapter = require('../../utils/enhanced-schema-adapter');
const apiClient = require('../../utils/api-client');
const logger = require('../../utils/logger');

const adapter = new EnhancedSchemaAdapter();
const moduleName = 'Customer';

describe('Module: Customer', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new Customer', async () => {
    const [url, payload] = ["/erp-apis/Customer",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","name":"string","nameAr":"string","categoryId":1,"marketType":"B2B","birthdate":"2025-11-26T16:29:05.635Z","photo":"string","tagIds":[1],"contactInfo":{"contactPhone":"string","contactEmail":"string","contactMobileCode":"string","contactMobile":"string","contactWebsite":"string","contactFax":"string","contactPersonPhone":"string","contactPersonMobileCode":"string","contactPersonMobile":"string","contactPersonEmail":"string","contactPersonName":"string"},"financialInfo":{"paymentTermId":1,"pricePolicyId":1,"allowCreditLimit":true,"creditLimit":1,"currencyId":1},"legalInfo":{"commercialRegistrationNumber":"string","taxIdentificationNumber":"string","street":"string","citySubdivisionName":"string","cityName":"string","postalZone":"string","countrySubEntity":"string","countryId":"string","buildingNumber":"string","additionalStreetName":"string","registrationName":"string","otherID":"string","nationalNumber":"string"},"accountingInfo":{"receivableAccountId":1,"salesAccountId":1,"salesReturnAccountId":1,"discountAccountId":1},"customerAddresses":[{"longitude":1,"latitude":1,"errorRadius":1}],"customerMarketPlaces":[{"externalIdentifier":"00000000-0000-0000-0000-000000000000","marketPlaceId":"00000000-0000-0000-0000-000000000000","salesManId":"00000000-0000-0000-0000-000000000000","address":"string"}]}];
    
    logger.info('Testing CREATE for Customer');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created Customer with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get Customer by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Customer",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for Customer with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read Customer');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update Customer', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Customer",{"id":"<createdId>","name":"string","nameAr":"string","categoryId":"<createdId>","marketType":"B2B","birthdate":"2025-11-26T16:29:05.636Z","photo":"string","tagIds":[1],"contactInfo":{"contactPhone":"string","contactEmail":"string","contactMobileCode":"string","contactMobile":"string","contactWebsite":"string","contactFax":"string","contactPersonPhone":"string","contactPersonMobileCode":"string","contactPersonMobile":"string","contactPersonEmail":"string","contactPersonName":"string"},"financialInfo":{"paymentTermId":"<createdId>","pricePolicyId":"<createdId>","allowCreditLimit":true,"creditLimit":1,"currencyId":"<createdId>"},"legalInfo":{"commercialRegistrationNumber":"string","taxIdentificationNumber":"string","street":"string","citySubdivisionName":"string","cityName":"string","postalZone":"string","countrySubEntity":"string","countryId":"<createdId>","buildingNumber":"string","additionalStreetName":"string","registrationName":"string","otherID":"<createdId>","nationalNumber":"string"},"accountingInfo":{"receivableAccountId":"<createdId>","salesAccountId":"<createdId>","salesReturnAccountId":"<createdId>","discountAccountId":"<createdId>"},"customerAddresses":[{"id":"<createdId>","longitude":1,"latitude":1,"errorRadius":1}],"customerMarketPlaces":[{"id":"<createdId>","externalIdentifier":"00000000-0000-0000-0000-000000000000","marketPlaceId":"<createdId>","salesManId":"<createdId>","address":"string"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for Customer with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated Customer');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete Customer', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/Customer/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for Customer with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted Customer');
  }, TEST_TIMEOUT);
});
