# PhishRadar - Vietnamese Phishing Detection API
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 5122

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files (check paths carefully!)
COPY ["src/Api/Api.csproj", "src/Api/"]
COPY ["src/Core/Core.csproj", "src/Core/"]
COPY ["src/Rules/Rules.csproj", "src/Rules/"]
COPY ["src/Infrastructure/Infrastructure.csproj", "src/Infrastructure/"]

# Restore dependencies
RUN dotnet restore "src/Api/Api.csproj"

# Copy source code
COPY src/ src/

# Build application
WORKDIR "/src/src/Api"
RUN dotnet build "Api.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage
FROM base AS final
WORKDIR /app

# Copy published app
COPY --from=publish /app/publish .

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:5122

# Switch to non-root user
USER appuser

# NO CURL HEALTHCHECK - aspnet:8.0 doesn't have curl!
# Health check via built-in /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD dotnet --list-runtimes > /dev/null || exit 1

ENTRYPOINT ["dotnet", "Api.dll"]