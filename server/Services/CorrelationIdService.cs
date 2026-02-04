namespace BffMicrosoftEntraID.Server.Services
{

	public interface ICorrelationIdService
	{
		string GetCorrelationId();
		void SetCorrelationId(string correlationId);
	}

	public class CorrelationIdService : ICorrelationIdService
	{
		private static readonly AsyncLocal<string?> _correlationId = new();

		public string GetCorrelationId()
		{
			return _correlationId.Value ?? throw new InvalidOperationException("Correlation ID has not been set.");
		}

		public void SetCorrelationId(string correlationId)
		{
			if (string.IsNullOrWhiteSpace(correlationId))
			{
				throw new ArgumentException("Correlation ID cannot be null or empty.", nameof(correlationId));
			}

			_correlationId.Value = correlationId;
		}
	}
}
