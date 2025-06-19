#!/usr/bin/env ruby

require 'json'
require 'optparse'
require 'net/http'
require 'uri'

class TerraformLockParser
  def initialize(file_path, debug = false)
    @file_path = file_path
    @urls = []
    @debug = debug
    @providers = []
  end

  def parse
    unless File.exist?(@file_path)
      raise "File not found: #{@file_path}"
    end

    puts "Step 1: Reading Terraform lock file..."
    content = File.read(@file_path)
    
    if @debug
      puts "=== DEBUG: File content preview ==="
      puts content[0..500]
      puts "=== END DEBUG ==="
    end
    
    puts "Step 2: Extracting provider information..."
    extract_urls_and_providers(content)
    
    if @debug
      puts "=== DEBUG: Providers found ==="
      @providers.each { |provider| puts "  #{provider[:org]}/#{provider[:name]}" }
      puts "=== END DEBUG ==="
    end
    
    puts "Step 3: Checking GitHub repositories..."
    check_github_repos
    
    puts "Step 4: Getting OSSF Security Scorecards..."
    check_security_scorecards
    
    puts "Step 5: Analyzing with AI..."
    analyze_with_openai
    
    @providers
  end

  def analyze_with_openai
    api_key = ENV['OPENAI_API_KEY']
    unless api_key
      puts "Warning: OPENAI_API_KEY not found. Skipping AI analysis."
      return
    end

    # Prepare simplified data for analysis
    analysis_data = {
      total_providers: @providers.length,
      providers: @providers.map do |provider|
        next unless provider[:security_scorecard] && !provider[:security_scorecard][:error]
        
        {
          name: provider[:full_name],
          overall_score: provider[:security_scorecard][:overall_score],
          github_exists: provider[:github_exists],
          key_issues: provider[:security_scorecard][:checks]&.select { |check| 
            check[:score] < 5 && ['Code-Review', 'Vulnerabilities', 'Binary-Artifacts', 'Token-Permissions', 
             'Dangerous-Workflow', 'Dependency-Update-Tool', 'SAST', 'Security-Policy'].include?(check[:name])
          }&.map { |check| 
            { name: check[:name], score: check[:score] }
          }
        }
      end.compact
    }

    puts "  Sending data to OpenAI..." if @debug

    begin
      uri = URI('https://api.openai.com/v1/chat/completions')
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 30
      http.read_timeout = 60

      request = Net::HTTP::Post.new(uri.path)
      request['Authorization'] = "Bearer #{api_key}"
      request['Content-Type'] = 'application/json'

      request.body = {
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity expert reviewing the output of various configurations for github repos for risks using OSSF scorecard. Summarize the ratings for the various providers that the scorecard gives us. Focus on critical security issues, overall risk assessment, and actionable recommendations. Keep it concise."
          },
          {
            role: "user",
            content: "Please analyze this OSSF Scorecard data for Terraform providers and provide a brief security risk assessment:\n\n#{JSON.pretty_generate(analysis_data)}"
          }
        ],
        max_tokens: 1000,
        temperature: 0.3
      }.to_json

      response = http.request(request)
      
      case response.code.to_i
      when 200
        result = JSON.parse(response.body)
        ai_analysis = result.dig('choices', 0, 'message', 'content')
        puts "\n" + "="*60
        puts "AI SECURITY ANALYSIS"
        puts "="*60
        puts ai_analysis
        puts "="*60
      else
        puts "  OpenAI API error: #{response.code}"
      end
      
    rescue => e
      puts "  AI analysis failed: #{e.message}"
    end
  end

  private

  def extract_urls_and_providers(content)
    # Extract URLs from various contexts in Terraform lock files
    
    # Direct HTTP/HTTPS URLs (catch all URLs first)
    http_urls = content.scan(/(https?:\/\/[^\s"'\]]+)/)
    http_urls.each do |match|
      url = match[0].gsub(/[,\]\}]*$/, '') # Remove trailing punctuation
      @urls << url
    end

    # Provider declarations with quotes - multiple patterns
    provider_patterns = [
      /provider\s+"([^"]+)"/,
      /provider\s+'([^']+)'/,
      /"([^"]*registry\.terraform\.io\/providers?\/[^"]+)"/,
      /'([^']*registry\.terraform\.io\/providers?\/[^']+)'/
    ]
    
    provider_patterns.each do |pattern|
      matches = content.scan(pattern)
      matches.each do |match|
        source = match[0]
        if source.include?('registry.terraform.io') && !source.start_with?('http')
          @urls << "https://#{source}"
          extract_provider_info(source)
        elsif source.count('/') == 2 && !source.start_with?('http') && !source.include?('registry.terraform.io')
          @urls << "https://registry.terraform.io/providers/#{source}"
          extract_provider_info(source)
        end
      end
    end

    # Look for registry URLs without protocol
    registry_patterns = [
      /registry\.terraform\.io\/providers?\/([a-zA-Z0-9\-_]+\/[a-zA-Z0-9\-_]+)/,
      /"(registry\.terraform\.io\/providers?\/[^"]+)"/,
      /'(registry\.terraform\.io\/providers?\/[^']+)'/
    ]
    
    registry_patterns.each do |pattern|
      matches = content.scan(pattern)
      matches.each do |match|
        registry_path = match[0]
        unless registry_path.start_with?('http')
          @urls << "https://#{registry_path}"
          extract_provider_info(registry_path)
        end
      end
    end

    # Look for any quoted strings that look like provider sources
    quoted_sources = content.scan(/"([a-zA-Z0-9\-_]+\/[a-zA-Z0-9\-_]+)"/)
    quoted_sources.each do |match|
      source = match[0]
      # Only convert simple two-part names that look like providers
      if source.count('/') == 1 && source =~ /^[a-zA-Z0-9\-_]+\/[a-zA-Z0-9\-_]+$/
        @urls << "https://registry.terraform.io/providers/#{source}"
        extract_provider_info(source)
      end
    end

    puts "  Found #{@providers.length} unique providers"
  end

  def extract_provider_info(source)
    clean_source = source.gsub(/^registry\.terraform\.io\/providers?\//, '')
    parts = clean_source.split('/')
    
    if parts.length >= 2
      org = parts[-2]
      provider_name = parts[-1]
      
      provider_info = {
        org: org,
        name: provider_name,
        full_name: "#{org}/#{provider_name}",
        registry_url: source.start_with?('http') ? source : "https://registry.terraform.io/providers/#{org}/#{provider_name}",
        github_repo: nil,
        github_exists: nil,
        security_scorecard: nil
      }
      
      @providers << provider_info unless @providers.any? { |p| p[:full_name] == provider_info[:full_name] }
    end
  end

  def check_github_repos
    existing_count = 0
    
    @providers.each do |provider|
      github_url = "https://github.com/#{provider[:org]}/terraform-provider-#{provider[:name]}"
      provider[:github_repo] = github_url
      
      begin
        uri = URI(github_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 10
        
        request = Net::HTTP::Head.new(uri.path)
        request['User-Agent'] = 'TerraformLockParser/1.0'
        
        response = http.request(request)
        
        case response.code.to_i
        when 200
          provider[:github_exists] = true
          existing_count += 1
          puts "  ✓ #{provider[:full_name]}" if @debug
        when 404
          provider[:github_exists] = false
          puts "  ✗ #{provider[:full_name]} - NOT FOUND" if @debug
        else
          provider[:github_exists] = "unknown"
          puts "  ? #{provider[:full_name]} - #{response.code}" if @debug
        end
        
      rescue => e
        provider[:github_exists] = "error"
        puts "  ✗ #{provider[:full_name]} - ERROR" if @debug
      end
      
      sleep(0.5)
    end
    
    puts "  Found #{existing_count}/#{@providers.length} repositories on GitHub"
  end

  def check_security_scorecards
    scored_count = 0
    total_score = 0
    
    @providers.each do |provider|
      next unless provider[:github_exists] == true
      
      github_url = provider[:github_repo]
      repo_path = github_url.gsub('https://github.com/', '')
      scorecard_url = "https://api.securityscorecards.dev/projects/github.com/#{repo_path}"
      
      begin
        uri = URI(scorecard_url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 15
        http.read_timeout = 15
        
        request = Net::HTTP::Get.new(uri.path)
        request['User-Agent'] = 'TerraformLockParser/1.0'
        request['Accept'] = 'application/json'
        
        response = http.request(request)
        
        case response.code.to_i
        when 200
          scorecard_data = JSON.parse(response.body)
          provider[:security_scorecard] = {
            overall_score: scorecard_data['score'],
            date: scorecard_data['date'],
            commit: scorecard_data['commit'],
            checks: scorecard_data['checks']&.map do |check|
              {
                name: check['name'],
                score: check['score'],
                reason: check['reason']
              }
            end
          }
          scored_count += 1
          total_score += scorecard_data['score']
          puts "  ✓ #{provider[:full_name]} - Score: #{scorecard_data['score']}" if @debug
        when 404
          provider[:security_scorecard] = { error: "not_found" }
          puts "  ✗ #{provider[:full_name]} - Not in scorecard database" if @debug
        else
          provider[:security_scorecard] = { error: "unknown" }
          puts "  ? #{provider[:full_name]} - #{response.code}" if @debug
        end
        
      rescue => e
        provider[:security_scorecard] = { error: "network_error" }
        puts "  ✗ #{provider[:full_name]} - ERROR" if @debug
      end
      
      sleep(1)
    end
    
    avg_score = scored_count > 0 ? (total_score / scored_count.to_f).round(2) : 0
    puts "  Scored #{scored_count}/#{@providers.length} repositories (avg: #{avg_score})"
  end
end

def main
  options = {}
  
  OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options]"
    
    opts.on('-f', '--file PATH', 'Path to Terraform lock file (.terraform.lock.hcl)') do |file|
      options[:file] = file
    end
    
    opts.on('-d', '--debug', 'Enable debug output') do
      options[:debug] = true
    end
    
    opts.on('-h', '--help', 'Show this help message') do
      puts opts
      exit
    end
    
    opts.on('-v', '--version', 'Show version') do
      puts "Terraform Lock Parser v2.0.0"
      exit
    end
  end.parse!

  # Default to .terraform.lock.hcl in current directory if no file specified
  lock_file = options[:file] || '.terraform.lock.hcl'

  begin
    puts "Terraform Provider Security Analysis"
    puts "=" * 40
    
    parser = TerraformLockParser.new(lock_file, options[:debug])
    providers = parser.parse
    
    puts "\nSUMMARY OF PROVIDERS:"
    puts "=" * 40
    
    providers.each do |provider|
      status = case provider[:github_exists]
      when true
        if provider[:security_scorecard] && !provider[:security_scorecard][:error]
          score = provider[:security_scorecard][:overall_score]
          color = score >= 7 ? "🟢" : score >= 5 ? "🟡" : "🔴"
          "#{color} Score: #{score}"
        else
          "⚪ No scorecard"
        end
      when false
        "❌ No GitHub repo"
      else
        "❓ Unknown"
      end
      
      puts "#{provider[:full_name].ljust(25)} #{status}"
    end
    
  rescue => e
    puts "Error: #{e.message}"
    exit 1
  end
end

if __FILE__ == $0
  main
end
