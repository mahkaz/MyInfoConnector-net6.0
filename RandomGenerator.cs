using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace sg.gov.ndi.MyInfoConnector
{
    /// <summary>
    /// Secure random generator
    /// https://stackoverflow.com/questions/42426420/how-to-generate-a-cryptographically-secure-random-integer-within-a-range
    /// </summary>
    internal class RandomGenerator : IDisposable
    {
        private readonly RandomNumberGenerator csp;

        /// <summary>
        /// Constructor
        /// </summary>
        public RandomGenerator()
        {
            csp = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Get random value
        /// </summary>
        /// <param name="minValue"></param>
        /// <param name="maxExclusiveValue"></param>
        /// <returns></returns>
        public int Next(int minValue, int maxExclusiveValue)
        {
            if (minValue == maxExclusiveValue) return minValue;

            if (minValue > maxExclusiveValue)
            {
                throw new ArgumentOutOfRangeException($"{nameof(minValue)} must be lower than {nameof(maxExclusiveValue)}");
            }

            var diff = (long)maxExclusiveValue - minValue;
            var upperBound = uint.MaxValue / diff * diff;

            uint ui;
            do
            {
                ui = GetRandomUInt();
            } while (ui >= upperBound);
            return (int)(minValue + (ui % diff));
        }

        private uint GetRandomUInt()
        {
            var randomBytes = GenerateRandomBytes(sizeof(uint));
            return BitConverter.ToUInt32(randomBytes, 0);
        }

        private byte[] GenerateRandomBytes(int bytesNumber)
        {
            var buffer = new byte[bytesNumber];
            csp.GetBytes(buffer);
            return buffer;
        }

        private bool _disposed;

        /// <summary>
        /// Public implementation of Dispose pattern callable by consumers.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected implementation of Dispose pattern.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                // Dispose managed state (managed objects).
                csp?.Dispose();
            }

            _disposed = true;
        }
    }
}
