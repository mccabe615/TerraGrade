
![terragrade](https://github.com/user-attachments/assets/6837c1d3-4e41-4f13-aa2d-5ad498a1b31a)


# Terraform Provider Security Analyzer

A Ruby script that analyzes Terraform lock files to assess the security posture of your provider dependencies using OSSF Security Scorecards and AI-powered analysis.

## Features

- 🔍 **Automatic Provider Detection** - Extracts all providers from `.terraform.lock.hcl` files
- 🐙 **GitHub Repository Verification** - Checks if provider source repositories exist
- 🛡️ **OSSF Security Scorecard Integration** - Fetches security scores from the OpenSSF Scorecard project
- 🤖 **AI-Powered Analysis** - Uses OpenAI to provide expert security risk assessment
- 📊 **Clean Summary Output** - Color-coded provider security status at a glance

## Prerequisites

- Ruby 2.7 or higher
- Internet connection for API calls
- Optional: OpenAI API key for AI analysis

## Installation

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/your-repo/terraform_lock_parser.rb
chmod +x terraform_lock_parser.rb
```

2. (Optional) Set up OpenAI API key for enhanced analysis:
```bash
export OPENAI_API_KEY="your-openai-api-key-here"
```

## Usage

### Basic Usage

Run the script in any directory containing a `.terraform.lock.hcl` file:

```bash
ruby terraform_lock_parser.rb
```

### Command Line Options

```bash
# Specify a custom lock file location
ruby terraform_lock_parser.rb --file /path/to/.terraform.lock.hcl

# Enable detailed debug output
ruby terraform_lock_parser.rb --debug

# Show help
ruby terraform_lock_parser.rb --help

# Show version
ruby terraform_lock_parser.rb --version
```

## How It Works

The script automatically performs these steps:

1. **📖 Reads Terraform Lock File** - Parses `.terraform.lock.hcl` to extract provider information
2. **🔍 Extracts Provider Information** - Identifies provider organizations and names
3. **🐙 Checks GitHub Repositories** - Verifies if `github.com/<org>/terraform-provider-<name>` exists
4. **🛡️ Gets OSSF Security Scorecards** - Fetches security scores from `api.securityscorecards.dev`
5. **🤖 Analyzes with AI** - Uses OpenAI to provide expert security assessment (if API key provided)

## Sample Output

```
Terraform Provider Security Analysis
========================================
Step 1: Reading Terraform lock file...
Step 2: Extracting provider information...
  Found 5 unique providers
Step 3: Checking GitHub repositories...
  Found 5/5 repositories on GitHub
Step 4: Getting OSSF Security Scorecards...
  Scored 4/5 repositories (avg: 7.2)
Step 5: Analyzing with AI...

============================================================
AI SECURITY ANALYSIS
============================================================
## Security Risk Assessment for Terraform Providers

### Overall Security Posture
Your Terraform providers show a generally strong security posture with 
an average OSSF score of 7.2/10. However, there are some areas that 
require attention.

### Critical Issues Identified
- **hashicorp/external**: Lower score (6.4) due to insufficient 
  dependency update automation
- **custom/provider**: Repository not found in scorecard database

### Recommendations
1. Enable Dependabot for all repositories scoring below 7.0
2. Implement security policies for custom providers
3. Consider alternatives for providers with consistently low scores

### Risk Priority
🟢 LOW: 3 providers with good security practices
🟡 MEDIUM: 1 provider needs dependency management improvements
🔴 HIGH: 1 provider requires security assessment
============================================================

SUMMARY OF PROVIDERS:
========================================
hashicorp/aws             🟢 Score: 8.2
hashicorp/external        🟡 Score: 6.4
hashicorp/http            🟢 Score: 7.8
hashicorp/null            🟢 Score: 7.1
custom/provider           ⚪ No scorecard
```

## Status Icons Explained

| Icon | Meaning |
|------|---------|
| 🟢 | **Good** - Security score ≥ 7.0 |
| 🟡 | **Fair** - Security score 5.0-6.9 |
| 🔴 | **Poor** - Security score < 5.0 |
| ⚪ | **No Data** - Repository found but no scorecard available |
| ❌ | **Not Found** - GitHub repository doesn't exist |
| ❓ | **Unknown** - Error checking repository |

## OSSF Security Scorecard

The script uses the [OpenSSF Scorecard](https://github.com/ossf/scorecard) project, which evaluates open source projects on various security criteria:

- **Code Review** - Whether code changes are reviewed before merging
- **Vulnerabilities** - Known security vulnerabilities in dependencies
- **Binary Artifacts** - Whether binary artifacts are present in source code
- **Token Permissions** - Whether GitHub tokens have minimal permissions
- **SAST** - Whether static analysis security testing is enabled
- **Security Policy** - Whether the project has a security policy
- **And more...**

Each check receives a score from 0-10, and the overall score is the average.

## AI Analysis

When an OpenAI API key is provided, the script sends a summary of the security data to GPT-4o-mini for expert analysis. The AI provides:

- Overall security posture assessment
- Identification of critical issues
- Actionable recommendations
- Risk prioritization

**Note**: Only essential security data is sent to OpenAI - no sensitive information from your Terraform configurations.

## API Rate Limits

The script includes respectful rate limiting:

- **GitHub API**: 0.5 second delay between requests
- **OSSF Scorecard API**: 1 second delay between requests
- **OpenAI API**: Single request for analysis

## Troubleshooting

### Common Issues

**"No URLs found"** - The script couldn't parse your lock file. Try `--debug` to see what's being detected.

**"Repository not found"** - The provider doesn't follow the standard `terraform-provider-<name>` naming convention.

**"Rate limited"** - You've hit API rate limits. Wait a few minutes and try again.

**"OpenAI API error"** - Check your API key and ensure you have access to the `gpt-4o-mini` model.

### Debug Mode

Use `--debug` flag to see detailed information about:
- File content being parsed
- Providers being detected
- API requests being made
- Detailed status of each step

## Security Considerations

- The script only reads your lock file - it doesn't access your actual Terraform configurations
- No sensitive data is sent to external APIs
- All API requests use HTTPS
- The script respects API rate limits and terms of service

## Contributing

Issues and pull requests welcome! Please ensure any changes maintain the security-focused nature of the tool.

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is for informational purposes only. Security scores should be considered as one factor in your overall security assessment. Always perform your own security due diligence when selecting and using third-party providers.
