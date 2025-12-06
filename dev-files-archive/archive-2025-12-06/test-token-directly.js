require("dotenv").config();
const axios = require("axios");

async function testTokenDirectly() {
  console.log("🔐 DIRECT TOKEN TEST");
  console.log("====================\n");

  const token = process.env.TOKEN;
  if (!token) {
    console.log("❌ No TOKEN found in environment");
    return;
  }

  const cleanToken = token.replace(/['"]/g, "").trim();
  const authHeader = cleanToken.startsWith("Bearer ")
    ? cleanToken
    : `Bearer ${cleanToken}`;

  console.log(`Token length: ${cleanToken.length}`);
  console.log(`Auth header length: ${authHeader.length}`);
  console.log(`Auth header preview: ${authHeader.substring(0, 30)}...\n`);

  // Test GET
  console.log("1. Testing GET request:");
  try {
    const getResponse = await axios.get(
      "https://microtecsaudi.com:2032/erp-apis/JournalEntry",
      {
        headers: { Authorization: authHeader },
      }
    );
    console.log(`   ✅ GET Status: ${getResponse.status}`);
  } catch (error) {
    console.log(`   ❌ GET Error: ${error.response?.status || error.message}`);
  }

  // Test POST with sample data
  console.log("\n2. Testing POST request:");
  const postData = {
    refrenceNumber: null,
    journalDate: new Date().toISOString().split("T")[0],
    periodId: "Period1",
    isHeaderDescriptionCopied: false,
    description: `Direct Test ${new Date().toISOString()}`,
    journalEntryLines: [
      {
        id: "00000000-0000-0000-0000-000000000000",
        accountId: 86,
        creditAmount: 0,
        currencyId: 4,
        currencyRate: 1,
        debitAmount: "100",
        lineDescription: "Direct API Test",
        createdOn: new Date().toISOString().split(".")[0],
        isVatLine: false,
        hasVat: false,
        costCenters: [],
      },
    ],
    journalEntryAttachments: [],
  };

  try {
    const postResponse = await axios.post(
      "https://microtecsaudi.com:2032/erp-apis/JournalEntry",
      postData,
      {
        headers: {
          Authorization: authHeader,
          "Content-Type": "application/json",
        },
      }
    );
    console.log(`   ✅ POST Status: ${postResponse.status}`);
    console.log(`   ✅ Response ID: ${postResponse.data}`);
  } catch (error) {
    console.log(`   ❌ POST Error: ${error.response?.status || error.message}`);
    if (error.response?.data) {
      console.log(`   Error details:`, error.response.data);
    }
  }
}

testTokenDirectly().catch(console.error);
