# Fix two defects from the v2 patch: stray commas in BuildBeaconJson chain
# and a missing escaped quote in the SendResult separator.
s = open('src/c2.cpp', encoding='utf-8').read()
Q, BS, NL = chr(34), chr(92), chr(10)

# 1. BuildBeaconJson: the run/ack lines must end with the C++ literal "<BS><Q>," + Q
#    (JSON comma INSIDE the literal, no trailing operator comma).
bad_run  = '      << ' + Q + BS + Q + 'run' + BS + Q + ':' + BS + Q + Q + '      << run  << ' + Q + BS + Q + ',' + Q + ',' + NL
good_run = '      << ' + Q + BS + Q + 'run' + BS + Q + ':' + BS + Q + Q + '      << run  << ' + Q + BS + Q + ',' + Q + NL
bad_ack  = '      << ' + Q + BS + Q + 'ack' + BS + Q + ':' + BS + Q + Q + '    << JsonEscape(ack) << ' + Q + BS + Q + ',' + Q + ',' + NL
good_ack = '      << ' + Q + BS + Q + 'ack' + BS + Q + ':' + BS + Q + Q + '    << JsonEscape(ack) << ' + Q + BS + Q + ',' + Q + NL
assert bad_run in s, 'bad run line not found'
assert bad_ack in s, 'bad ack line not found'
s = s.replace(bad_run, good_run, 1)
s = s.replace(bad_ack, good_ack, 1)
print('ok: BuildBeaconJson commas')

# 2. SendResult: separator after sid must close the value quote first.
bad_sep  = ' + sid + ' + Q + ',' + BS + Q + 'tid' + BS + Q + ':' + BS + Q + Q
good_sep = ' + sid + ' + Q + BS + Q + ',' + BS + Q + 'tid' + BS + Q + ':' + BS + Q + Q
assert bad_sep in s, 'bad separator not found'
s = s.replace(bad_sep, good_sep, 1)
print('ok: SendResult separator')

open('src/c2.cpp', 'w', encoding='utf-8', newline='').write(s)
print('fixes written')
