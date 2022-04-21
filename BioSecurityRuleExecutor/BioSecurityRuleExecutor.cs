using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using RulesEngine;
using static RulesEngine.Extensions.ListofRuleResultTreeExtension;
using RulesEngine.Exceptions;
using RulesEngine.HelperFunctions;
using RulesEngine.Interfaces;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using RulesEngine.Models;

using Moq;

namespace BioSecurityRuleExecutor
{
    public static class BioSecurityRuleExecutor
    {
        [FunctionName("BioSecurityRuleExecutor")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string operationName = req.Query["operation"];
            string responseMessage = "";

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            //dynamic data = JsonConvert.DeserializeObject(requestBody);
            //the body of the message has the payload for case and request 


            //ExpandoObject deserialisation
            var converter = new ExpandoObjectConverter();
            dynamic data = JsonConvert.DeserializeObject<ExpandoObject>(requestBody, converter);
            
            

            var helper = new RulesEngineHelper();
            var rulesEngineInstance = helper.GetRulesEngine(operationName + ".json", null, operationName);

            var ruleParams = new List<RuleParameter>();
            var obj = Utils.GetTypedObject(data);
            ruleParams.Add(new RuleParameter($"var", obj));
            var dataforRules = ruleParams?.ToArray();


            List<RuleResultTree> result = await rulesEngineInstance.ExecuteAllRulesAsync(operationName, dataforRules);

            
            
            

            switch (operationName)
            {
                case "validateCase":
                    var reResponse = new ReResponseValidateCase();

                    foreach (RuleResultTree ruleResultItem in result)
                    {

                        reResponse.ruleDetails.Add(new ReResponseValidateCase.RuleDetails
                        {
                            RuleName = ruleResultItem.Rule.RuleName,
                            IsSuccess = ruleResultItem.IsSuccess,
                            ExceptionMessage = ruleResultItem.ExceptionMessage
                        });
                    }

                    return new OkObjectResult(reResponse);

                    break;
                case "assessTaskList":

                    var reResponseTaskList = new ReResponseAssessTaskList();

                    dynamic biconConditions = data.BiconData[0].ImportConditions;
                    foreach (dynamic condition in biconConditions){
                        
                        reResponseTaskList.taskList.Add(new ReResponseAssessTaskList.TaskList
                        {
                            ConditionType = condition.ConditionType,
                            Condition = condition.Condition,
                            ConditionCategory = condition.ConditionCategory,
                            Mandatory = condition.Mandatory,
                            MediaEvidence = condition.MediaEvidence,
                            InputCategory = condition.InputCategory,
                            Status = string.IsNullOrEmpty("") ? "Pending" : "Completed",
                            Value = ""
                        });
                    }

                    return new OkObjectResult(reResponseTaskList);
                    break;


                case "assessRisk":
                case "assessRiskAtBorder":
                    var reResponseAssessRisk = new ReResponseAssessRisks();

                    dynamic taskList = data.TaskList;
                    
                    
                    var falseResults = result.Where( c => c.IsSuccess == false);
                    var falseResultsCount = falseResults.Count();

                    var trueResults = result.Where(c => c.IsSuccess == true);
                    var trueResultsCount = trueResults.Count();
                    reResponseAssessRisk.RiskRating =  trueResults.Count() / ((falseResults.Count() + trueResults.Count()) * 100);
                    if (reResponseAssessRisk.RiskRating < 40)
                    {
                        reResponseAssessRisk.OverallStatus = "High";
                    }
                    else if (reResponseAssessRisk.RiskRating < 70)
                    {
                        reResponseAssessRisk.OverallStatus = "Medium";
                    }
                    else if(reResponseAssessRisk.RiskRating <= 100)
                    {
                        reResponseAssessRisk.OverallStatus = "Low";
                    }


                    foreach (dynamic condition in taskList)
                    {

                        reResponseAssessRisk.assessments.AddItem(new ReResponseAssessTaskList.TaskList
                        {
                            ConditionType = condition.ConditionType,
                            Condition = condition.Condition,
                            ConditionCategory = condition.ConditionCategory,
                            Mandatory = condition.Mandatory,
                            MediaEvidence = condition.MediaEvidence,
                            InputCategory = condition.InputCategory,
                            Status = condition.Status,
                            Value = condition.Value,
                        });
                    }

                    foreach (RuleResultTree ruleResultItem in result)
                    {

                        reResponseAssessRisk.validations.AddItem(new ReResponseValidateCase.RuleDetails
                        {
                            RuleName = ruleResultItem.Rule.RuleName,
                            IsSuccess = ruleResultItem.IsSuccess,
                            ExceptionMessage = ruleResultItem.ExceptionMessage
                        });
                    }


                    return new OkObjectResult(reResponseAssessRisk);

                    break;
            };



            


            
            responseMessage = string.IsNullOrEmpty(responseMessage)
                ? "Please provide a valid operation name for the consumer"
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

    

    public class ReResponseValidateCase : Attribute
    {

        public class RuleDetails {
            public string RuleName { get; set; }
            public bool   IsSuccess { get; set; }
            public string ExceptionMessage { get; set; }
            public IEnumerable<RuleResultTree> ChildResults { get; set; }
        }
        public List<RuleDetails> ruleDetails;

        public ReResponseValidateCase() {
            this.ruleDetails = new List<ReResponseValidateCase.RuleDetails>();
        }

        public void AddItem(RuleDetails rule) {
            this.ruleDetails.Add(rule);
        }
    }


    public class ReResponseAssessTaskList : Attribute 
    {

        public class TaskList {
            public string ConditionType { get; set; }
            public string Condition { get; set; }
            public string ConditionCategory { get; set; }
            public string Mandatory { get; set; }
            public string MediaEvidence { get; set; }
            public string InputCategory { get; set; }
            public string Status { get; set; }
            public string Value { get; set; }

        }

        public List<TaskList> taskList;

        public ReResponseAssessTaskList()
        {
            this.taskList = new List<ReResponseAssessTaskList.TaskList>();
        }
        public void AddItem(TaskList task)
        {
            this.taskList.Add(task);
        }
    }

    [ReResponseValidateCase]
    [ReResponseAssessTaskList]
    public class ReResponseAssessRisks
    {
        public int RiskRating { get; set; }
        public string OverallStatus { get; set; }
        public ReResponseValidateCase validations;
        public ReResponseAssessTaskList assessments;

        public ReResponseAssessRisks() {
            this.validations = new ReResponseValidateCase();
            this.assessments = new ReResponseAssessTaskList();
        }

        public void AddItem(ReResponseValidateCase.RuleDetails rule = null, ReResponseAssessTaskList.TaskList task = null) {
            if (rule != null)
            {
                this.validations.AddItem(rule);
            }
            if (task != null)
            {
                this.assessments.AddItem(task);
            }

        }
    }



}

