# Common honeypot behaviors
# 1. Check if it logs your IP immediately
UNIQUE=$(uuidgen)
echo "SELECT '$UNIQUE';" | nc mainnet.validator.haedal.xyz 3306

# 2. Test if connections from different IPs get different responses
# (would need to run from different source IPs)

# 3. Check connection limits per IP
for i in {1..100}; do
    (nc -z mainnet.validator.haedal.xyz 3306 2>&1 | grep -q succeeded && echo "$i: Connected") &
    if [ $((i % 10)) -eq 0 ]; then sleep 0.1; fi
done
wait | wc -l

# 4. Test known honeypot responses
# Cowrie honeypot check
echo -ne "SSH-2.0-OpenSSH_7.4\r\n" | nc -w 3 mainnet.validator.haedal.xyz 22

# Dionaea honeypot check (often runs MySQL)
echo -ne "\x00\x00\x00\x00" | nc -w 3 mainnet.validator.haedal.xyz 3306 | grep -a "Access denied"
