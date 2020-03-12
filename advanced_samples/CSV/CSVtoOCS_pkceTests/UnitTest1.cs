using System;
using Xunit;

namespace CSVtoOCSTests
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            Assert.True(CSVtoOCS.Program.MainAsync(true).Result);
        }
    }
}