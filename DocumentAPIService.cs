using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class DocumentAPIService
    {
        private readonly AuthorizedHttpClient _httpClient;

        public DocumentAPIService()
        {
            _httpClient = new AuthorizedHttpClient();
        }

        public async Task<string> GetErmsDocuments(string flowVariant, string businessKey)
        {
            // Set the specific headers
            _httpClient.Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.Client.DefaultRequestHeaders.Add("FlowVariant", flowVariant);

            // Construct the URL with the businessKey parameter
            string baseUrl = "https://jxwwdocumentapid.aginsurance.intranet/VIJXWWdocumentapi/api/v2/ermsdocuments";
            string url = $"{baseUrl}?businessKey={Uri.EscapeDataString(businessKey)}";

            // Make the API call
            HttpResponseMessage response = await _httpClient.Client.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                string result = await response.Content.ReadAsStringAsync();
                return result;
                // Process the result
            }
            else
            {
                return response.StatusCode.ToString();
            }
        }
        public async Task<string> SearchFinancingFunds(int top,
                                                       int skip,
                                                       List<string> employerAccountNumbers,
                                                       string clientNumber,
                                                       string regulationNumber,
                                                       List<string> poolNumbers)
        {
            // Construct the request body
            var requestBodyObj = new
            {
                paging = new { top, skip },
                financingFundSearchParams = new
                {
                    employerAccountNumbers,
                    clientNumber,
                    regulationNumber,
                    poolNumbers
                }
            };


            string requestBody = JsonConvert.SerializeObject(requestBodyObj);

            // Set the specific headers
            _httpClient.Client.DefaultRequestHeaders.Accept.Clear();
            _httpClient.Client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Set the URL
            string url = "https://financingfunds.domain.dev.ebhc.ag.intranet/api/v1/financingfunds/search";

            // Make the API call
            HttpResponseMessage response = await _httpClient.Client.PostAsync(url, new StringContent(requestBody, Encoding.UTF8, "application/json"));

            if (response.IsSuccessStatusCode)
            {
                // Process the result
                string result = await response.Content.ReadAsStringAsync();
                return result;
            }
            else
            {
                return response.StatusCode.ToString();
            }
        }
    }
}
