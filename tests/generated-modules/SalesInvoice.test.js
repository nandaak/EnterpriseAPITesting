/**
 * Auto-generated test for module: SalesInvoice
 * Generated: 2025-12-01T13:40:51.240Z
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
const moduleName = 'SalesInvoice';

describe('Module: SalesInvoice', () => {
  let createdId = null;
  const TEST_TIMEOUT = 30000;

  
  test('CREATE - should create new SalesInvoice', async () => {
    const [url, payload] = ["/erp-apis/SalesInvoice",{"externalIdentifier":"00000000-0000-0000-0000-000000000000","externalCode":"string","invoiceDate":"2025-11-26T16:29:05.637Z","invoiceDueDate":"2025-11-26T16:29:05.637Z","description":"string","warehouseId":1,"warehouseName":"string","customerId":1,"customerName":"string","customerCreditLimit":1,"pricePolicyId":1,"currencyId":1,"salesManId":"00000000-0000-0000-0000-000000000000","salesManName":"string","currencyName":"string","currencyRate":1,"paymentTermId":1,"reference":"string","sourceType":"Direct","applicationSource":"ERP","isLinkedToAdvancedPayment":true,"salesInvoiceSources":[{"sourceId":"00000000-0000-0000-0000-000000000000","sourceCode":"string"}],"posSessionId":"00000000-0000-0000-0000-000000000000","salesInvoiceDetails":[{"externalIdentifier":"00000000-0000-0000-0000-000000000000","barCode":"string","barCodeId":1,"itemId":1,"itemCode":"string","itemName":"string","itemVariantId":1,"itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":1,"itemCategoryNameAr":"string","itemCategoryNameEn":"string","categoryType":{},"description":"string","uomId":"00000000-0000-0000-0000-000000000000","uomCode":"string","uomNameAr":"string","uomNameEn":"string","quantity":1,"price":1,"cost":1,"isVatIncluded":true,"vatPercentage":1,"taxId":1,"notes":"string","itemStockBatchHeaderId":"00000000-0000-0000-0000-000000000000","pricePolicyDetailId":1,"invoiceEntryMode":{},"trackingType":{},"hasExpiryDate":true,"sourceId":"00000000-0000-0000-0000-000000000000","sourceDetailId":"00000000-0000-0000-0000-000000000000","isServiceItem":true,"isProductItem":true,"salesInvoiceTracking":{},"salesDetailDiscounts":[{}],"salesInvoiceDetailIngredients":[{}]}],"salesInvoiceBalances":[{"dueAmount":1,"dueDate":"2025-11-26T16:29:05.637Z","dueBalance":1}],"posInvoicePayments":[{"amount":1,"paymentMethodType":{},"paymentMethodCode":"string","paymentMethodId":1}],"salesDiscounts":[{"discountPolicyId":1,"discountPolicyName":"string","discountPercentage":1,"isActive":true,"salesOrderHeaderId":"00000000-0000-0000-0000-000000000000"}],"enableWorkflow":true}];
    
    logger.info('Testing CREATE for SalesInvoice');
    logger.debug(`URL: ${url}`);
    logger.debug(`Payload: ${JSON.stringify(payload, null, 2)}`);

    const response = await apiClient.post(url, payload);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();

    // Extract and store ID
    createdId = response.data.id || response.data.Id || response.data.ID;
    
    if (createdId) {
      logger.success(`Created SalesInvoice with ID: ${createdId}`);
      adapter.storeId(moduleName, createdId);
    }
  }, TEST_TIMEOUT);
  
  
  test('READ - should get SalesInvoice by ID', async () => {
    if (!createdId) {
      logger.warn('Skipping READ - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesInvoice",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing READ for SalesInvoice with ID: ${createdId}`);

    const response = await apiClient.get(url);

    expect(response.status).toBe(200);
    expect(response.data).toBeDefined();
    
    logger.success('Successfully read SalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('UPDATE - should update SalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping UPDATE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesInvoice",{"id":"<createdId>","invoiceDate":"2025-11-26T16:29:05.637Z","invoiceDueDate":"2025-11-26T16:29:05.637Z","description":"string","warehouseId":"<createdId>","warehouseName":"string","customerId":"<createdId>","customerName":"string","customerCreditLimit":1,"pricePolicyId":"<createdId>","currencyId":"<createdId>","currencyName":"string","currencyRate":1,"paymentTermId":"<createdId>","reference":"string","salesManId":"<createdId>","salesManName":"string","sourceType":"Direct","applicationSource":"ERP","isLinkedToAdvancedPayment":true,"salesInvoiceSources":[{"id":"<createdId>","sourceId":"<createdId>","sourceCode":"string"}],"salesInvoiceDetails":[{"externalIdentifier":"00000000-0000-0000-0000-000000000000","id":"<createdId>","barCode":"string","barCodeId":"<createdId>","itemId":"<createdId>","itemCode":"string","itemName":"string","itemVariantId":"<createdId>","itemVariantCode":"string","itemVariantNameEn":"string","itemVariantNameAr":"string","categoryId":"<createdId>","itemCategoryNameAr":"string","itemCategoryNameEn":"string","categoryType":{},"description":"string","uomId":"<createdId>","uomCode":"string","uomNameAr":"string","uomNameEn":"string","quantity":1,"price":1,"cost":1,"discountPercentage":1,"discountAmount":1,"isVatIncluded":true,"vatPercentage":1,"taxId":"<createdId>","notes":"string","itemStockBatchHeaderId":"<createdId>","pricePolicyDetailId":"<createdId>","invoiceEntryMode":{},"trackingType":{},"hasExpiryDate":true,"sourceDetailId":"<createdId>","sourceId":"<createdId>","isServiceItem":true,"salesInvoiceTracking":{},"salesDetailDiscounts":[{}]}],"salesInvoiceBalances":[{"id":"<createdId>","dueAmount":1,"dueDate":"2025-11-26T16:29:05.637Z","dueBalance":1}],"salesDiscounts":[{"id":"<createdId>","discountPolicyId":"<createdId>","discountPolicyName":"string","discountPercentage":1,"isActive":true,"salesOrderHeaderId":"<createdId>"}]}], createdId);
    const [url, payload] = prepared;
    
    logger.info(`Testing UPDATE for SalesInvoice with ID: ${createdId}`);

    const response = await apiClient.put(url, payload);

    expect(response.status).toBe(200);
    
    logger.success('Successfully updated SalesInvoice');
  }, TEST_TIMEOUT);
  
  
  test('DELETE - should delete SalesInvoice', async () => {
    if (!createdId) {
      logger.warn('Skipping DELETE - no created ID');
      return;
    }

    const prepared = adapter.prepareOperation(["/erp-apis/SalesInvoice/<createdId>",{}], createdId);
    const [url] = prepared;
    
    logger.info(`Testing DELETE for SalesInvoice with ID: ${createdId}`);

    const response = await apiClient.delete(url);

    expect(response.status).toBe(200);
    
    logger.success('Successfully deleted SalesInvoice');
  }, TEST_TIMEOUT);
});
