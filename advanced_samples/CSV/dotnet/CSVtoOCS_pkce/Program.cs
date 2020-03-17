﻿
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using OSIsoft.Data;
using OSIsoft.Data.Reflection;
using OSIsoft.Identity;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using CsvHelper;
using IdentityModel.Client;
using IdentityModel.OidcClient;

namespace CSVtoOCS
{
    public class Program
    {
        public static Exception toThrow = null;
        public static bool success = true;

        static List<TemperatureReadingsWithIds> dataList;
        static IEnumerable<string> streamsIdsToSendTo;
        static ISdsDataService dataService;
        static ISdsMetadataService metaService;
        private static bool createStreams = true;
        static SdsStream stream1, stream2;
        static bool test = false;

        static void Main(string[] args)
        {
            string fileLocationIn = "datafile.csv";
            if (args.Length > 0)
                fileLocationIn = args[0];
            MainAsync(fileLocation: fileLocationIn).GetAwaiter().GetResult();
        }

        public static async Task<bool> MainAsync(bool test = false, string fileLocation = "datafile.csv")
        {
            success = true;

            try
            {
                // Import data in.  Use csv reader and custom class to make it simple
                using (var reader = new StreamReader(fileLocation))
                using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                {
                    dataList = csv.GetRecords<TemperatureReadingsWithIds>().ToList();
                }
                // Use Linq to get the distinct StreamIds we need.  
                streamsIdsToSendTo = dataList.Select(dataeEntry => dataeEntry.StreamId).Distinct();

                //Get Configuration information about where this is sending to
                IConfiguration configuration = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json")
                    .AddJsonFile("appsettings.test.json", optional: true)
                    .Build();

                var tenantId = configuration["TenantId"];
                var namespaceId = configuration["NamespaceId"];
                var resource = configuration["Resource"];
                var clientId = configuration["ClientID"];

                if (SystemBrowser.openBrowser == null)
                {
                    SystemBrowser.openBrowser = new OpenSystemBrowser();
                }
                else
                {
                    test = true;
                    SystemBrowser.password = configuration["Password"];
                    SystemBrowser.userName = configuration["UserName"];
                }

                (configuration as ConfigurationRoot).Dispose();
                var uriResource = new Uri(resource);                               

                // Setup access to OCS
                AuthenticationHandler_PKCE authenticationHandler = new AuthenticationHandler_PKCE(tenantId, clientId, resource);

                SdsService sdsService = new SdsService(new Uri(resource), authenticationHandler);
                dataService = sdsService.GetDataService(tenantId, namespaceId);
                metaService = sdsService.GetMetadataService(tenantId, namespaceId);

                if (createStreams)
                {
                    metaService = sdsService.GetMetadataService(tenantId, namespaceId);

                    SdsType typeToCreate = SdsTypeBuilder.CreateSdsType<TemperatureReadings>();
                    typeToCreate.Id = "TemperatureReadings";
                    await metaService.GetOrCreateTypeAsync(typeToCreate);
                    stream1 = new SdsStream { Id = "stream1", TypeId = typeToCreate.Id };
                    stream2 = new SdsStream { Id = "stream2", TypeId = typeToCreate.Id };
                    stream1 = await metaService.GetOrCreateStreamAsync(stream1);
                    stream2 = await metaService.GetOrCreateStreamAsync(stream2);
                }

                // Loop over each stream to send to and send the data as one call.
                foreach (string streamId in streamsIdsToSendTo)
                {
                    // Get all of the data for this stream in a list
                    var valueToSend = dataList.Where(dataEntry => dataEntry.StreamId == streamId)  //gets only appropriate data for stream
                                              .Select(dataEntry => new TemperatureReadings(dataEntry)) // transforms it to the right data
                                              .ToList(); // needed in IList format for insertValues
                    await dataService.InsertValuesAsync(streamId, valueToSend);
                }

                //checks to make sure values are written
                await CheckValuesWrittenASync();
            }
            catch (Exception ex)
            {
                success = false;
                Console.WriteLine(ex.Message);
                toThrow = ex;
            }
            finally
            {
                if (!createStreams)
                {
                    // if we just created the data lets just remove that
                    // Do Delete
                    await DeleteValuesAsync();
                    // Do Delete check
                    await CheckDeletesValuesAsync();
                }
                else
                {
                    // if we created the types and streams, lets remove those too
                    await RunInTryCatch(metaService.DeleteStreamAsync, stream1.Id);
                    await RunInTryCatch(metaService.DeleteStreamAsync, stream2.Id);
                    await RunInTryCatch(metaService.DeleteTypeAsync, stream1.TypeId);
                    
                    // Check deletes
                    await RunInTryCatchExpectException(metaService.GetStreamAsync, stream1.Id);
                    await RunInTryCatchExpectException(metaService.GetStreamAsync, stream2.Id);
                    await RunInTryCatchExpectException(metaService.GetTypeAsync, stream1.TypeId);
                }
            }

            if (toThrow != null)
                throw toThrow;
            return success;
        }

        /// <summary>
        /// Use this to run a method that you don't want to stop the program if there is an exception
        /// </summary>
        /// <param name="methodToRun">The method to run.</param>
        /// <param name="value">The value to put into the method to run</param>
        private static async Task RunInTryCatch(Func<string, Task> methodToRun, string value)
        {
            try
            {
                await methodToRun(value);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Got error in {methodToRun.Method.Name} with value {value} but continued on:" + ex.Message);
                if (toThrow == null)
                {
                    success = false;
                    toThrow = ex;
                }
            }
        }


        /// <summary>
        /// Use this to run a method that you don't want to stop the program if there is an exception, and you expect an exception
        /// </summary>
        /// <param name="methodToRun">The method to run.</param>
        /// <param name="value">The value to put into the method to run</param>
        private static async Task RunInTryCatchExpectException(Func<string, Task> methodToRun, string value)
        {
            try
            {
                await methodToRun(value);

                Console.WriteLine($"Got error.  Expected {methodToRun.Method.Name} with value {value} to throw an error but it did not:");
            }
            catch(Exception ex)
            {

            }
        }

        private static async Task CheckValuesWrittenASync()
        {
            foreach (string streamId in streamsIdsToSendTo)
            {
                try
                {
                    var lastVal = await dataService.GetLastValueAsync<TemperatureReadings>(streamId);
                    if (lastVal == null && toThrow == null)
                    {
                        throw new Exception($"Value for {streamId} was not found");
                    }
                }
                catch (Exception ex)
                {
                    if (toThrow == null)
                    {
                        success = false;
                        toThrow = ex;
                    }
                }
            }
        }

        private static async Task CheckDeletesValuesAsync()
        {
            foreach (string streamId in streamsIdsToSendTo)
            {
                try
                {
                    var lastVal = await dataService.GetLastValueAsync<TemperatureReadings>(streamId);
                    if (lastVal != null && toThrow == null)
                    {
                        throw new Exception($"Value for {streamId} was found");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Got error in seeing that removed values are gone in {streamId} but continued on:" + ex.Message);
                    if (toThrow == null)
                    {
                        success = false;
                        toThrow = ex;
                    }
                }
            }
        }

        private static async Task DeleteValuesAsync()
        {
            foreach (string streamId in streamsIdsToSendTo)
            {

                try
                {
                    var timeStampToDelete = dataList.Select(o => o.Timestamp);
                    await dataService.RemoveValuesAsync(streamId, timeStampToDelete);
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"Got error in removing values in {streamId} but continued on:" + ex.Message);
                    if (toThrow == null)
                    {
                        success = false;
                        toThrow = ex;
                    }
                }
            }
        }

        public class TemperatureReadingsWithIds : TemperatureReadings
        {
            public string StreamId { get; set; }
        }
        
        public class TemperatureReadings
        {
            public TemperatureReadings()
            {
            }

            public TemperatureReadings (TemperatureReadingsWithIds tempReading)
            {
                Timestamp = tempReading.Timestamp;
                Temperature1 = tempReading.Temperature1;
                Temperature2 = tempReading.Temperature2;
                Code = tempReading.Code;
            }


            [SdsMember(IsKey = true)]
            public DateTime Timestamp { get; set; }
            public int Temperature1 { get; set; }
            public double Temperature2 { get; set; }
            public string Code { get; set; }
        }
    }
}
