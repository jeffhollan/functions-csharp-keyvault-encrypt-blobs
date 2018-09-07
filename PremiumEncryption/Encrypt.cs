using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.WindowsAzure.Storage;
using System;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Threading.Tasks;
using System.IO;
using System.Collections.Generic;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using System.Security.Cryptography;

namespace PremiumEncryption
{
    public static class Encrypt
    {
        private static CloudStorageAccount storageAccount = CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("AzureWebJobsStorage"));
        private static CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
        private static AzureServiceTokenProvider tokenProvider = new AzureServiceTokenProvider();
#if DEBUG
        private static KeyVaultClient keyClient = GenerateKeyVaultDEBUG();
#else
        private static KeyVaultClient keyClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
#endif
        [FunctionName("Encrypt")]
        public static async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post")]HttpRequest req, 
            ILogger log)
        {
            log.LogInformation("Encrypt function received a request.");

            var taskList = new List<Task>();

            var blobContainer = blobClient.GetContainerReference(req.Query["container"]);

            var encryptor = await CreateEncryptionKey(blobContainer);
            BlobContinuationToken token = null;
            do
            {
                var resultSegment = await blobContainer.ListBlobsSegmentedAsync(token);
                token = resultSegment.ContinuationToken;
                foreach (IListBlobItem listBlob in resultSegment.Results)
                {
                    CloudBlockBlob blob = listBlob as CloudBlockBlob;
                    if(blob != null)
                    {
                        taskList.Add(encryptFileAsync(blob, blobContainer, encryptor));
                    }
                }
            }
            while (token != null);

            await Task.WhenAll(taskList);

            return new OkResult();
        }


        private static async Task<ICryptoTransform> CreateEncryptionKey(CloudBlobContainer blobContainer)
        {
            Aes aes = Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
            var encrypted = await keyClient.EncryptAsync(Environment.GetEnvironmentVariable("EncryptionKeyID"), "RSA-OAEP", aes.Key);
            CloudBlockBlob keyBlob = blobContainer.GetBlockBlobReference(".key");
            await keyBlob.UploadFromByteArrayAsync(encrypted.Result, 0, encrypted.Result.Length);
            return aes.CreateEncryptor();
        }


        private static async Task encryptFileAsync(CloudBlockBlob blob, CloudBlobContainer blobContainer, ICryptoTransform encryptor)
        {
            CloudBlockBlob eBlob = blobContainer.GetBlockBlobReference(blob.Name + ".encrypted");
            Stream outStream = new MemoryStream();
            var inStream = await blob.OpenReadAsync();
            new CryptoStream(inStream, encryptor, CryptoStreamMode.Read).CopyTo(outStream);
            await eBlob.UploadFromStreamAsync(outStream);
        }

        private static KeyVaultClient GenerateKeyVaultDEBUG()
        {
            return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(Utils.Utils.GetToken));
        }



    }
}
