#!/usr/bin/env ruby

require 'openssl'
require 'socket'

CA_PASSPHRASE = 'dummy passphrase'

OpenSSL::Random.seed File.read('/dev/random', 16)

begin
  Dir.mkdir('mitm-proxy')
rescue Errno::EEXIST
end

def init_ca_cert
  sha1 = OpenSSL::Digest::SHA1.new

  # CA の情報を設定
  name = OpenSSL::X509::Name.new
  name.add_entry 'C',  'JP'
  name.add_entry 'ST', 'Osaka'
  name.add_entry 'DC', 'Kita-ku'
  name.add_entry 'O',  'INGAGE Inc.'
  name.add_entry 'CN', 'Masm11 CA'

  # CA の秘密鍵/公開鍵を生成
  rsa = OpenSSL::PKey::RSA.generate(2048)

  # CA の秘密鍵を保存
  File.write('ca.pkey', rsa.export(OpenSSL::Cipher::Cipher.new('aes256'), CA_PASSPHRASE))

  # CA 証明書を作成
  cert = OpenSSL::X509::Certificate.new
  cert.not_before = Time.now
  cert.not_after = Time.now + 3600 * 24 * 365
  cert.public_key = rsa.public_key
  cert.serial = 1
  cert.issuer = name
  cert.subject = name
  ext = OpenSSL::X509::Extension.new('basicConstraints', OpenSSL::ASN1.Sequence([OpenSSL::ASN1::Boolean(true)]))
  cert.add_extension(ext)
  cert.sign(rsa, sha1)

  # CA 証明書を保存
  File.write('ca.crt', cert.to_pem)
end

def read_ca_cert
  return OpenSSL::PKey::RSA.new(File.read('ca.pkey'), CA_PASSPHRASE),
         OpenSSL::X509::Certificate.new(File.read('ca.crt'))
end

def get_cert(ca_pkey, ca_cert, domain)
  begin
    return OpenSSL::PKey::RSA.new(File.read("mitm-proxy/#{domain}.pkey")),
           OpenSSL::X509::Certificate.new(File.read("mitm-proxy/#{domain}.crt"))
  rescue Errno::ENOENT
  end

  sha1 = OpenSSL::Digest::SHA1.new

  # サーバの情報を設定
  name = OpenSSL::X509::Name.new
  name.add_entry 'C' , 'JP'
  name.add_entry 'ST', 'Osaka'
  name.add_entry 'DC', 'Kita-ku'
  name.add_entry 'O' , 'INGAGE Inc.'
  name.add_entry 'CN', domain

  # サーバの秘密鍵/公開鍵を生成
  rsa = OpenSSL::PKey::RSA.generate 2048

  # サーバの秘密鍵を書き出し
  File.write("mitm-proxy/#{domain}.pkey", rsa.export)

  # サーバ証明書を作成
  crt = OpenSSL::X509::Certificate.new
  crt.not_before = Time.now
  crt.not_after  = Time.now + 3600 * 24 * 365
  crt.public_key = rsa.public_key
  crt.serial = Time.now.to_i
  crt.issuer = ca_cert.issuer
  crt.subject = name
  crt.sign(ca_pkey, sha1)
  File.write("mitm-proxy/#{domain}.crt", crt.to_pem)

  return rsa, crt
end

def sysread_line(sock)
  buf = ''
  loop do
    b = sock.sysread(1)
    buf += b
    return buf if buf =~ /\n\z/
  end
end

def serve(ca_pkey, ca_cert, sock)
  line = sysread_line(sock).chomp
  if line !~ /\ACONNECT\s+(.*):(\d+)\s/
    raise 'Bad connect: ' + line
  end
  host = $1
  port = $2.to_i

  loop do
    line = sysread_line(sock).chomp
    break if line == ''
  end

  cs = TCPSocket.open(host, port)
  cs = OpenSSL::SSL::SSLSocket.new(cs)
  cs.connect
  cs.post_connection_check(host)

  sock.syswrite "HTTP/1.1 200 OK\r\n\r\n"

  pkey, cert = get_cert(ca_pkey, ca_cert, host)

  ctxt = OpenSSL::SSL::SSLContext.new('TLSv1_2_server')
  ctxt.cert = cert
  ctxt.key = pkey

  sock = OpenSSL::SSL::SSLSocket.new(sock, ctxt)
  sock.accept

  begin
    loop do
      rs = IO.select([sock, cs])
      rs = rs.first.first
      if rs == sock
        buf = sock.sysread(1024)
        if buf.nil?    # EOF
          break
        end
        cs.syswrite(buf)
      elsif rs == cs
        buf = cs.sysread(1024)
        if buf.nil?    # EOF
          break
        end
        sock.syswrite(buf)
      else
        raise 'sock? cs?'
      end
    end
  rescue EOFError
  end
end

if ARGV[0] == '--init'
  init_ca_cert
end

ca_pkey, ca_cert = read_ca_cert

Socket.tcp_server_loop('127.0.0.1', 8000) do |sock, addr|
  fork do
    serve(ca_pkey, ca_cert, sock)
    exit(0)
  end
  sock.close
end
