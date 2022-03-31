using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Moq;
using RulesEngine;
using RulesEngine.Models;
using System.Collections.Generic;
using System.Dynamic;
using static RulesEngine.Extensions.ListofRuleResultTreeExtension;
using Newtonsoft.Json.Converters;
using RulesEngine.Exceptions;
using RulesEngine.HelperFunctions;
using RulesEngine.Interfaces;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;

namespace BioSecurityRuleExecutor
{
    public static class BioSecurityRuleExecutor
    {
        [FunctionName("BioSecurityRuleExecutor")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string operationName = req.Query["operation"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            //dynamic data = JsonConvert.DeserializeObject(requestBody);
            //the body of the message has the payload for case and request 


            //ExpandoObject deserialisation
            var converter = new ExpandoObjectConverter();
            var data = JsonConvert.DeserializeObject<ExpandoObject>(requestBody, converter);
            


            var helper = new RulesEngineHelper();
            var rulesEngineInstance = helper.GetRulesEngine("Rules.json", null, operationName);

            List<RuleResultTree> result = await rulesEngineInstance.ExecuteAllRulesAsync(operationName, data);


            var reResponse = new RulesEngineResponse();
            
            reResponse.OverallStatus = result.Any(c => c.IsSuccess == false) == true ? "One or more rules failed!" : "Success";
            foreach (RuleResultTree ruleResultItem in result)
            {
               
                reResponse.ruleDetails.Add( new RulesEngineResponse.RuleDetails { RuleName = ruleResultItem.Rule.RuleName,
                                                                                  IsSuccess = ruleResultItem.IsSuccess,
                                                                                  ExceptionMessage = ruleResultItem.ExceptionMessage } );
            }

            string responseMessage = JsonConvert.SerializeObject(reResponse);
            

            responseMessage = string.IsNullOrEmpty(operationName)
                ? "Please provide a valid operationName for the consumer"
                : responseMessage;

            return new OkObjectResult(responseMessage);
        }
    }

    public class RulesEngineHelper
    {

        public RulesEngine.RulesEngine GetRulesEngine(string filename, ReSettings reSettings = null, string WorkflowName = "")
        {
            var data = GetFileContent(filename);
            var mockLogger = new Mock<ILogger>();
            return new RulesEngine.RulesEngine(new string[] { data }, mockLogger.Object, reSettings);
        }
        public string GetFileContent(string filename)
        {
            var parent = Directory.GetParent(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
            return File.ReadAllText(Path.Combine(parent.FullName, filename));
        }
    }

    public class RulesEngineResponse
    {
        public int RiskRating { get; set; }
        public string OverallStatus { get; set; }

        public class RuleDetails {
            public string RuleName { get; set; }
            public bool IsSuccess { get; set; }
            public string ExceptionMessage { get; set; }
            public IEnumerable<RuleResultTree> ChildResults { get; set; }
        }
        public List<RuleDetails> ruleDetails;

        public RulesEngineResponse() {
            this.ruleDetails = new List<RulesEngineResponse.RuleDetails>();
        }
    }   
    }

