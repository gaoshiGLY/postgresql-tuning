#!/usr/bin/env perl

use strict;
use warnings;
use Config;

my $os = {};
$os->{name}    = $Config{osname};
$os->{arch}    = $Config{archname};
$os->{version} = $Config{osvers};

my %db_params = ();

# missing needed modules count
my $mnmc = 0;

# Extended processing of command line options 
$mnmc += tryLoad( "Getopt::Long", {} );

# PostgreSQL database driver for the DBI module
$mnmc += tryLoad(
    "DBD::Pg",
    {
        '/usr/local/bin/cpan' => 'cpan DBD::Pg',
        '/etc/debian_version' => 'apt-get install -y libdbd-pg-perl',
        '/etc/redhat-release' => 'yum install -y perl-DBD-Pg'
    }
);

# Database independent interface for Perl
$mnmc += tryLoad(
    "DBI",
    {
        '/usr/local/bin/cpan' => "cpan DBI",
        '/etc/debian_version' => 'apt-get install -y libdbi-perl',
        '/etc/redhat-release' => 'yum install -y perl-DBI'
    }
);

# Color screen output using ANSI escape sequences
$mnmc += tryLoad(
    "Term::ANSIColor",
    {
        '/usr/local/bin/cpan' => 'cpan DBI',
        '/etc/debian_version' => 'apt-get install -y perl-modules',
        '/etc/redhat-release' => 'yum install -y perl-Term-ANSIColor'
    }
);
if ( $mnmc > 0 ) {
    # 输出到标准错误输出
    print STDERR "# Please install the missing Perl modules above.\n";
    exit 1;
}

sub tryLoad {
    my ( $module, $cmds ) = @_;
    eval("use $module");
    if ($@) {
        print STDERR "# Missing Perl module '$module'. Please install it.\n";
        foreach ( keys %$cmds ) {
            print $cmds->{$_} . "\n" if -f $_;
        }
        return 1;
    }
    else {
        return 0;
    }
}

# 判断是否具有root权限
{
    if(`id -u` == 0){

    }else{
        print color('red')."Please run perl with root permission. Exit checking...\n".color('reset');
        exit 0;
    }
}

my $script_version = "0.6";
my $script_name    = "postgresql-tuning.pl";
my $min_sec        = 60;
my $hour_sec       = 60 * 60;
my $day_sec        = 24 * 60 * 60;

my $host                            = undef;
my $username                        = undef;
my $password                        = undef;
my $database                        = undef;
my $port                            = undef;
my $pgpassFile                      = $ENV{HOME} . '/.pgpass';
my $help                            = 0;
my $work_mem_per_connection_percent = 150;

# -o BatchMode=yes|no 当BatchMode=yes时，表示将不会显示交互式口令输入，而是直接失败，从而避免批处理的时候卡住。当BatchMode=no时，将会提示用户输入密码
my @Ssh_opts = ('BatchMode=yes');
my $ssd      = 0;
GetOptions(
    "host=s"     => \$host,
    "user=s"     => \$username,
    "username=s" => \$username,
    "pass:s"     => \$password,
    "password:s" => \$password,
    "db=s"       => \$database,
    "database=s" => \$database,
    "port=i"     => \$port,
    "help"       => \$help,
    "wmp=i"      => \$work_mem_per_connection_percent,
    "sshopt=s"   => \@Ssh_opts,
    "ssd"        => \$ssd,
) or useage(1);

sub usage {
	my $return=shift;
	print STDERR "usage: perl $script_name --host [ hostname | /var/run/postgresql ] [--user username] [--password password] [--database database] [--port port] [--wmp 150]\n";
	print STDERR "\t[--sshopt=Name=Value]...\n";
	print STDERR "\t[--ssd]\n";
	print STDERR "If available connection informations can be read from \$PGHOST, \$PGPORT, \$PGDATABASE, \$PGUSER, \$PGPASSWORD\n";
	print STDERR "For security reasons, prefer usage of password in ~/.pgpass\n";
	print STDERR "\thost:port:database:username:password\n";
	print STDERR "  --wmp: average number of work_mem buffers per connection in percent (default 150)\n";
	print STDERR "  --sshopt: pass options to ssh (example --sshopt=Port=2200)\n";
	print STDERR "  --ssd: force storage detection as non rotational drives\n";
	exit $return;
}

print "$script_name version $script_version\n";
if ($help) {
    usage(0);
}

# ssh options
my $ssh_opts = '';
foreach (@Ssh_opts) {
    $ssh_opts .= '-o ' . $_;
}

# host
if ( !defined($host) ) {
    if ( defined( $ENV{PGHOST} ) ) {
        $host = $ENV{PGHOST};
    }
    else {
        $host = '/var/run/postgresql';
    }
}

# port
if ( !defined($port) ) {
    if ( defined( $ENV{PGPORT} ) ) {
        $port = $ENV{PGPORT};
    }
    else {
        $port = 5432;
    }
}

# database
if ( !defined($database) ) {
    if ( defined( $ENV{PGDATABASE} ) ) {
        $database = $ENV{PGDATABASE};
    }
    else {
        $database = 'template1';    # 测试postgres库也可以,template1防止万一
    }
}

# user
if ( !defined($username) ) {
    if ( defined( $ENV{PGUSER} ) ) {
        $username = $ENV{PGUSER};
    }
    else {
        $username = 'postgres';
    }
}

# if not specified password, get it from ~/.pgpass
if ( !defined($password) ) {
    if ( defined( $ENV{PGPASSWORD} ) ) {
        $password = $ENV{PGPASSWORD};
    }
    else {
        if ( defined( $ENV{PGPASSFILE} ) ) {
            $pgpassFile = $ENV{PGPASSFILE};
        }
    }
    if ( open( PGPASS, '<', $pgpassFile ) ) {
        while ( my $line = <PGPASS> ) {
            chomp($line);
            next if $line =~ /^\s*#/;
            my ( $pgp_host, $pgp_port, $pgp_database, $pgp_username, $pgp_password, $pgp_more ) = split( /(?<!\\):/, $line );
            next if ( !defined($pgp_password) or defined($pgp_more) );    # 跳过异常行
            next if ( !pgpass_match( 'host',     $host,     $pgp_host ) );
            next if ( !pgpass_match( 'port',     $port,     $pgp_port ) );
            next if ( !pgpass_match( 'database', $database, $pgp_database ) );
            next if ( !pgpass_match( 'username', $username, $pgp_username ) );
            $password = pgpass_unescape($pgp_password);
            last;
        }
        close(PGPASS);
    }

    # default
    if ( !defined($password) ) {
        $password = '';
    }
}

sub pgpass_match {
    my ( $type, $var, $pgp_var ) = @_;
    $pgp_var = pgpass_unescape($pgp_var);
    return 1 if $pgp_var eq '*';
    return 1 if $pgp_var eq $var;
    return 1 if $type eq 'host' and $pgp_var eq 'localhost' and $var =~ m/^\//;
    return 0;
}

sub pgpass_unescape {
    my ($value) = @_;
    $value =~ s/\\(.)/$1/g; # match all
    return $value;
}

if(!defined($host)){
    print STDERR "Missing host\n";
    print STDERR "\tset \$PGHOST environmental variable\n or\tadd --host option\n";
    usage(1);
}

if(!defined($username)){
    print STDERR "Missing username\n";
    print STDERR "\tset \$PGUSER environmental variable\n or\tadd --user option\n";
    usage(1);
}

if(!defined($password)){
    print STDERR "Missing password\n";
    print STDERR "\tconfigure ~/.pgpass\nor\tset \$PGPASSWORD environmental variable\nor\tadd --password option\n";
    usage(1);
}

# OS command check
print "Checking if OS command available and can work properly on $host...\n";

# LANG=C是最早最简单的C语言环境（标准ASCII码），因为[a-z]都是连贯小写的，如果设置为别的语言环境，就不会按照ASCII码连续小写的排序了
# LC_ALL=C 是为了去除所有本地化的设置，让命令能正确执行
my $os_cmd_prefix  = 'LANG=C LC_ALL=C ';
my $can_run_os_cmd = 0;
if ( $host =~ /^\// ) {
    $os_cmd_prefix = '';
}
elsif ( $host =~ /^localhost$/ ) {
    $os_cmd_prefix = '';
}
elsif ( $host =~ /127\.[0-9]+\.[0-9]+\.[0-9]+$/ ) {
    $os_cmd_prefix = '';
}
elsif ( $host =~ /^[a-zA-Z0-9.]+$/ ) {
    $os_cmd_prefix = "ssh $ssh_opts $host";
}
else {
    die("Invalid host $host");
}
if ( defined( os_cmd("true") ) ) {
    $can_run_os_cmd = 1;
    print_report_ok("OS command OK");
}
else {
    print_report_bad("Unable to run OS command, report will be incomplete");
    add_advice( "report", "urgent","Please configure your .ssh/config to allow postgresql-tuning.pl to connect via ssh to $host without password authentication. This will allow to collect more system informations");
}

# Database connection
print "Connecting to $host:$port database $database with user $username...\n";
# AutoCommit : If true, then database changes cannot be rolled-back (undone). If false, then database changes automatically occur within a "transaction", which must either be committed or rolled back using the commit or rollback methods.
# RaiseError : The RaiseError attribute can be used to force errors to raise exceptions rather than simply return error codes in the normal way. It is "off" by default. When set "on", any method which results in an error will cause the DBI to effectively do a die("$class $method failed: $DBI::errstr"), where $class is the driver class and $method is the name of the method that failed. E.g.,
#              If you turn RaiseError on then you'd normally turn PrintError off. If PrintError is also on, then the PrintError is done first (naturally).
# PrintError : The PrintError attribute can be used to force errors to generate warnings (using warn) in addition to returning error codes in the normal way. When set "on", any method which results in an error occurring will cause the DBI to effectively do a warn("$class $method failed: $DBI::errstr") where $class is the driver class and $method is the name of the method which failed. E.g.,
#              By default, DBI->connect sets PrintError "on".
my $dbh = DBI->connect("dbi:Pg:dbname=$database;host=$host;port=$port;",$username,$password,{AutoCommit=>1,RaiseError=>1,PrintError=>0});

# Collect db configurations
my $users     = select_all_hashref( "SELECT * FROM pg_user", "usename" );
my $superuser = $users->{$username}->{usesuper};
my $settings  = select_all_hashref( "SELECT * FROM pg_settings", "name" );
my @HDD       = qw//;
my @SSD       = qw//;
my @Extensions;
my %TPS = undef;
if ( min_version('9.1') ) {
    @Extensions = select_one_column("SELECT extname FROM pg_extension");
}
else {
    print_report_warn( "pg_entension does not exist in " . get_setting('server_version') );
}
my %advices;

if ($superuser) {
    print_report_ok("Current user has superuser's rights.");
}
else {
    print_report_bad( "Current user does not have superuser rights. Report will be incomplete." );
    add_advice( "report", "urgent","User an account with superuser privileges to get a complete report." );
}

# Report data
print_header_1("OS information");

{
    if(!$can_run_os_cmd){
        print_report_unknown("Unable to run OS commands on $host. For now you will not get OS information.");
    }else{
        my $kernel_ver = os_cmd("cat /proc/version");
        chomp($kernel_ver);
        print_report_info("OS: $os->{name}\n\t   Kernel version: $kernel_ver\n\t   Arch: $os->{arch}");

        if($kernel_ver =~ /Linux version ([\d]+\.[\d]+)\.[\d]+/){
            # print $1."####################################\n";
            if($1 == 3.2){
                print_report_bad("You are on the kernel 3.2. It is worth to upgrade it due to a significant read performance downgrade");
                add_advice("kernel","urgent","You are on the kernel 3.2. It is worth to upgrade it due to a significant read performance downgrade");
            }elsif($1 < 3.13){
                print_report_warn("You should upgrade to 3.13 or a later version due to the IO issues fixes dramatically improving IO consumption for reads");
                add_advice("kernel","urgent","You should upgrade to 3.13 or a later version due to the IO issues fixes dramatically improving IO consumption for reads")
            }
        }

        # Memory
        if($os->{name} eq 'darwin'){
            # -S：累积模式 -n<次数>：循环显示的次数
            my $os_mem = os_cmd("top -l 1 -S -n 0");
            $os->{mem_used} = standard_units($os_mem =~ /PhysMem: (\d+)([GMK])/);
            $os->{mem_free} = standard_units($os_mem =~ /(\d+)([GMK]) unused\./);
            $os->{mem_total} = $os->{mem_used} + $os->{mem_free};
            $os->{swap_used} = standard_units($os_mem =~ /Swap:\W+(\d+)([GMK])/);
            $os->{swap_free} = standard_units($os_mem =~ /Swap:\W+\d+[GMK] \+ (\d+)([GMK]) free/);
            $os->{swap_total} = $os->{used} + $os->{free};
        }else{
            my $os_mem = os_cmd("free -b");
            ($os->{mem_total},$os->{mem_used},$os->{mem_free},$os->{mem_shared},$os->{buffers},$os->{mem_cached}) = ($os_mem =~ /Mem:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)/);
            ($os->{swap_total},$os->{swap_used},$os->{swap_free}) = ($os_mem =~ /Swap:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)/);
        }
        print_report_info("OS total memory: ".format_size($os->{mem_total}));

        # print "##################  $os->{mem_total}  ######################\n";

        # Overcommit
        if($os->{name} eq 'darwin'){
            print_report_unknown("No information on memory overcommitment on MacOS.");
        }else{
            my $overcommit_memory = get_sysctl('vm.overcommit_memory');
            if($overcommit_memory != 2){
                print_report_bad("Memory overcommitment is allowed on the system. This can lead the OOM Killer killing some PostgreSQL process, which will cause a PostgreSQL server restart (crash recovery)");
                add_advice('sysctl','urgent','set vm.overcommit_memory=2 in /etc/sysctl.conf and run sysctl -p to reload it. This will disable memory overcommitment and avoid postgresql killed by OOM Killer.');
                my $overcommit_ratio = get_sysctl('vm.overcommit_ratio');
                print_report_info("sysctl vm.overcommit_ratio=$overcommit_ratio");
                if($overcommit_ratio <= 50){
                    print_report_bad("vm.overcommit_ratio is too small, you will not be able to use more than $overcommit_ratio*RAM+SWAP for applications");
                }elsif($overcommit_ratio > 90){
                    print_report_bad("vm.overcommit_ratio is too high, you need to keep free space for the kernel");
                }
            }else{
                print_report_ok("vm.overcommit_memory is good:no memory overcommitment");
            }
        }

        # Hardware
        my $hypervisor = undef;
        if($os->{name} ne 'darwin'){
            my $systemd = os_cmd('systemd-detect-virt --vm');
            if(defined($systemd)){
                if($systemd =~ m/(\S+)/){
                    $hypervisor = $1 if($1 ne 'none');
                }
            }else{
                my @dmesg = os_cmd("dmesg");
                foreach my $line(@dmesg){
                    if($line =~ /vmware/i){
                        $hypervisor = 'VMware';
                        last;
                    }elsif($line =~ /kvm/i){
                        $hypervisor = 'KVM';
                        last;
                    }elsif($line =~ /xen/i){
                        $hypervisor = 'XEN';
                        last;
                    }elsif($line =~ /vbox/i){
                        $hypervisor = 'VirtualBox';
                        last;
                    }elsif($line =~ /hyper-v/i){
                        $hypervisor = 'Hyper-V';
                        last;
                    }
                }
            }
        }
        if(defined($hypervisor)){
            print_report_info("Running in $hypervisor hypervisor");
        }else{
            print_report_info("RUnning on physical machine");
        }
        
        # I/O scheduler
        my %active_schedulers;
        if($os->{name} eq 'darwin'){
            print_report_unknown("No I/O scheduler information on MacOS");
        }else{
            my $disks_list = os_cmd("ls /sys/block/");
            if(!defined($disks_list)){
                print_report_unknown("Unable to identify disks");
            }else{
                my $disk_is_HDD = 0;
                my @disks = split(/\n/,$disks_list);
                my @warn_disks = qw();
                # my @hdd_disks = qw();
                # my @ssd_disks = qw();
                foreach my $disk(@disks){
                    next if($disk eq '.' or $disk eq '..');
                    next if($disk =~ /^sr/); # exclude cdrom

                    # Scheduler
                    my $disk_schedulers = os_cmd("cat /sys/block/$disk/queue/scheduler");
                    chomp($disk_schedulers);
                    unless($disk_schedulers =~ /\[[\d\D]*deadline\]/){
                        push @warn_disks,$disk;
                    }
                    # print "################################## $disk_schedulers ###############################\n";
                    if(!defined($disk_schedulers)){
                        print_report_unknown("Unable to identify scheduler for disk $disk");
                    }else{
                        # chomp($disk_schedulers);
                        next if($disk_schedulers eq 'none');

                        foreach my $scheduler(split(/ /,$disk_schedulers)){
                            if($scheduler =~ /^\[([a-z-]+)\]$/){
                                $active_schedulers{$1}++;
                            }
                        }
                    }

                    # Detect SSD or HDD
                    if($ssd){
                        $disk_is_HDD = 0;
                    }else{
                        $disk_is_HDD = os_cmd("cat /sys/block/$disk/queue/rotational");
                        if(!defined($disk_is_HDD)){
                            print_report_unknown("Unable to identify if disk $disk is rotational");
                        }else{
                            chomp($disk_is_HDD);
                        }
                    }
                    if($disk_is_HDD == 1){
                        push @HDD,$disk;
                    }elsif($disk_is_HDD == 0){
                        push @SSD,$disk;
                    }
                    # $HDD += $disk_is_HDD;
                    # push @HDD,$disk;
                }
                # my $SSDs = @disks - $HDD;
                print_report_info("Current machine contains ". scalar @disks ." hard drive(s): ".scalar @SSD." SSD(s) and ".scalar @HDD." HDD(s)\n\t\tHDD: @HDD\n\t\tSSD: @SSD");
                print_report_info("Currently using I/O scheduler(s): ".join(',',keys(%active_schedulers)));
                print_report_warn("@warn_disks 's I/O scheduler are not deadline") if @warn_disks > 0;
            }
        }
        # if(defined($hypervisor) && defined(@HDD) && @HDD > 0){
        if(defined($hypervisor) && (@HDD > 0 || @SSD > 0)){
            print_report_warn("On virtual machines, /sys/block/DISK/queue/rotational is not accurate. Use the --ssd arg if the VM in running on a SSD storage");
            add_advice("report","urgent","Use the --ssd arg if the VM in running on a SSD storage");
        }
        if(defined($hypervisor) && $active_schedulers{'cfq'}){
            print_report_bad("CFQ scheduler is bad on virtual machines (hypervisor and/or storage is already doing I/O scheduling)");
            add_advice("system","urgent","Configure your system to use noop or deadline(recommended) I/O scheduler when on virtual machines:\necho deadline > /sys/block/sdX/queue/scheduler\nupdate your kernel parameters line with elevator=deadline to keep this parameter at next reboot");
        }
    }

    # Readahead
    {
        my $readahead = os_cmd("/sbin/blockdev --getra /dev/sda");
        chomp($readahead);
        if(!defined($readahead)){
            print_report_unknown("File read-ahead is unknown");
        }elsif($readahead < 256){
            print_report_warn("File read-ahead($readahead) is less than default. This value can be set higher in newer hardware (recommend 16384).");
        }else{
            print_report_ok("File read-ahead is ok");
        }
    }

    # Transparent HugePages
    {
        my $transparent_hugepages = os_cmd("cat /sys/kernel/mm/transparent_hugepage/enabled");
        # chomp($transparent_hugepages);
        # my @params = split(/ /,$transparent_hugepages);
        # print "@params\n";
        if(!defined($transparent_hugepages)){
            print_report_unknown("Transparent HugePages is unknown");
        }else{
            if($transparent_hugepages =~ /\[never\]/){
                print_report_ok("Transparent HugePages is 'never'");
            }else{
                print_report_warn("Setting Transparent HugePages to 'never' will be good for database perfomance");
            }
        }
    }
}

# my @test = qw//;
# print scalar @test;

sub print_report_bad {
    print_report('bad',shift);
}

sub print_report_info {
    print_report('info',shift);
}

sub print_report_ok {
    print_report('ok',shift);
}

sub print_report_unknown {
    print_report('unknown',shift);
}

sub print_report_warn {
    print_report('warn',shift);
}

sub print_report_todo {
    print_report('todo',shift);
}

sub print_report_debug {
    print_report('debug',shift);
}

sub print_report {
    my ($level,$message) = @_;
    if($level eq 'ok'){
        print STDOUT color('green')  ."[OK]       ".color('reset').$message."\n";
    }elsif($level eq 'warn'){
        print STDOUT color('yellow') ."[WARN]     ".color('reset').$message."\n";
    }elsif($level eq 'bad'){
        print STDERR color('red')    ."[BAD]      ".color('reset').$message."\n";
    }elsif($level eq 'info'){
        print STDERR color('white')  ."[INFO]     ".color('reset').$message."\n";
    }elsif($level eq 'todo'){
        print STDERR color('megenta')."[TODO]     ".color('reset').$message."\n";
    }elsif($level eq 'unknown'){
        print STDERR color('cyan')   ."[UNKNOWN]  ".color('reset').$message."\n";
    }elsif($level eq 'debug'){
        print STDERR color('magenta')."[DEBUG]    ".color('reset').$message."\n";
    }else{
        print STDERR "ERROR: bad report type $level\n";
        exit 1;
    }
}

sub add_advice {
    my ($category,$priority,$advice) = @_;
    die("unknown priority $priority") if($priority !~ /(urgent|medium|low)/);
    push(@{$advices{$category}{$priority}},$advice);
}

sub select_all_hashref {
    my ($query,$key) = @_;
    if(!defined($query) or !defined($key)){
        print STDERR "ERROR: Missing query or key\n";
        exit 1;
    }
    my $sth = $dbh->prepare($query);
    $sth->execute();
    return $sth->fetchall_hashref($key);
}

sub min_version {
    my $min_version = shift;
    my $cur_version = get_setting('server_version');
    $cur_version =~ s/(devel|rc).*//; # clean devel or RC
    my($min_major,$min_minor) = split(/\./,$min_version);
    my($cur_major,$cur_minor) = split(/\./,$cur_version);
    if($cur_major > $min_major){
        return 1;
    }elsif($cur_major == $min_major){
        if(defined($min_minor)){
            if($cur_minor >= $min_minor){
                return 1;
            }else{
                return 0;
            }
        }else{
            return 1;
        }
    }
    return 0;
}

sub get_setting {
    my $name = shift;
    if(!defined($settings->{$name})){
        print STDERR "ERROR: setting $name does not exist\n";
        exit 1;
    }else{
        return standard_units($settings->{$name}->{setting},$settings->{$name}->{unit});
    }
}

sub standard_units { # convert to B
    my $value = shift;
    my $unit = shift;
    return $value if !$unit or $unit eq 'B';
    return $value * 1024 if $unit eq 'kB' || $unit eq 'K';
    return $value * 1024 * 8 if $unit eq '8kB';
    return $value * 16 * 1024 if $unit eq '16kB';
    return $value * 1024 * 1024 if $unit eq 'M';
    return $value * 1024 * 1024 * 1024 if $unit eq 'G';
    return $value.'s' if $unit eq 's';
    return $value.'ms' if $unit eq 'ms';
}

sub select_one_column {
    my($query) = @_;
    if(!defined($query)){
        print STDERR "ERROR: Missing query\n";
        exit 1;
    }
    my $sth = $dbh->prepare($query);
    $sth->execute();
    my @Result;
    while(my $result = $sth->fetchrow_arrayref()){
        push(@Result,@{$result}[0]);
    }
    return @Result;
}

sub print_header_1 {
    print_header(1,shift);
}

sub print_header_2 {
    print_header(2,shift);
}

sub print_header {
    my($level,$title) = @_;
    my $sep = '';
    if($level == 1){
        print color('bold bright_cyan');
        $sep = '=';
    }elsif($level == 2){
        print color('bold cyan');
        $sep = '-';
    }else{
        warn("Unknown level $level for title $title");
    }
    print $sep x 5 . "  $title  ". $sep x 5;
    print color('reset');
    print "\n";
}

# print `id -u`;

sub os_cmd {
    my $command = $os_cmd_prefix.shift;
    local $SIG{__WARN__} = sub {};
    my $result = `$command 2>&1`; # 将标准错误输出到标准输出中 2: 标准错误  >: 重定向  &1: 标准输出的引用
    if( $? == 0){ # 上一个命令的退出状态
        return $result;
    }else{
        warn("Command $command failed");
        return undef;
    }
}

sub format_size {
    my $size = shift;
    my @units = ('B','KB','MB','GB','TB','PB');
    my $unit_index = 0;
    return 0 if !defined($size);
    while($size > 1024){
        $size /= 1024;
        $unit_index++;
    }
    return sprintf("%.2f %s",$size,$units[$unit_index]);
}

sub get_sysctl {
    my $name = shift;
    $name =~ s/\./\//g;
    my $value = os_cmd("cat /proc/sys/$name");
    if(!defined($value)){
        print_report_unknown("Unable to read sysctl $name");
        return undef;
    }else{
        chomp($value);
        return $value;
    }
}

# Database instance information
print_header_1("Database instance information");

## Version
{
    print_header_2("Version");
    my $version = get_setting('server_version');
    if($version =~ /(devel|rc)/){
        print_report_bad("You are using version $version which is a Development Snapshot or Release Candidate: DO NOT USE IN PRODUCTION!");
        add_advice("version","urgent","Use a stable version (not a Development Snapshot or Release Candidate)");
    }
    if($version =~ /(\d+)\.(\d+)/){
        $version = $1;
    }
    if(min_version('11')){
        print_report_ok("You're using the latest major v.$version");
    }elsif(min_version('10')){
        print_report_warn("You're using major v.$version which is not the latest version");
        add_advice("version","low","Upgrade to the latest version");
    }elsif(min_version('9.0')){
        print_report_warn("You're using major v.$version which is not the latest version");
        add_advice("version","low","Upgrade to the latest version");
    }elsif(min_version('8.0')){
        print_report_bad("You're using major v.$version which is very old");
        add_advice("version","medium","Upgrade to the latest version");
    }else{
        print_report_bad("You're using version v.$version which is very old and is not supported by this script");
        add_advice("version","high","Upgrade to the latest version");
    }
}

## Uptime
{
    print_header_2("Uptime");
    my $uptime = select_one_value("SELECT extract(epoch from now() - pg_postmaster_start_time())"); # convert each value to a number of seconds using EXTRACT(EPOCH FROM ...), then subtract the results
    print_report_info("Service uptime: ".format_epoch_to_time($uptime));
    if($uptime < $day_sec){
        print_report_warn("Uptime is less than 1 day. $script_name result may not be accurate");
    }
}

sub select_one_value {
    my($query) = @_;
    if(!defined($query)){
        print STDERR "ERROR: Missing query\n";
        exit 1;
    }
    my $sth = $dbh->prepare($query);
    $sth->execute();
    if(my $result = $sth->fetchrow_arrayref()){
        return @{$result}[0];
    }else{
        return undef;
    }
}

sub format_epoch_to_time {
    my $epoch = shift;
    my $time = '';
    if($epoch > $day_sec){
        my $days = sprintf("%d",$epoch / $day_sec);
        $time .= $days.'d';
        $epoch = $epoch % $day_sec;
    }
    if($epoch > $hour_sec){
        my $hours = sprintf("%2d",$epoch / $hour_sec);
        $epoch = $epoch % $hour_sec;
        $time .= " $hours"."h";
    }
    if($epoch > $min_sec){
        my $mins = sprintf("%2d",$epoch / $min_sec);
        $epoch = $epoch % $min_sec;
        $time .= " $mins"."m";
    }
    $time .= " $epoch"."s";
    return $time;
}

## Database count(except template)
{
    print_header_2("Database");
    my @Databases = select_one_column("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn;");
    print_report_info("Database count (except template): ".scalar(@Databases));
    print_report_info("Database list (except template): @Databases");
}

## Extensions
{
    print_header_2("Extensions");
    print_report_info("Number of activated extensions: ".scalar(@Extensions));
    print_report_info("Activated extensions: @Extensions");
    if(grep(/pg_stat_statements/,@Extensions)){
        print_report_info("Extension pg_stat_statements is enabled");
    }else{
        print_report_warn("Extensions pg_stat_statements is disabled in database $database");
        add_advice("extension","low","Enable pg_stat_statements in database $database to collect statistics on all queries (not only queries longer the log_min_duration_statement in logs)");
    }
}

## Users
# 建议：可以增加查看用户数等用户信息
{
    print_header_2("Users");
    my @ExpiringSoonUsers = select_one_column("SELECT usename FROM pg_user WHERE valuntil < now() + interval '7 days'");
    if(@ExpiringSoonUsers > 0){
        print_report_warn("Some user account will expire in less than 7 days: ".join(',',@ExpiringSoonUsers));
    }else{
        print_report_ok("No user account will expire in less than 7 days");
    }
    if($superuser){
        my @BadPasswordUsers = select_one_column("SELECT usename FROM pg_shadow WHERE passwd='md5'||md5(usename||usename)");
        if(@BadPasswordUsers > 0){
            print_report_warn("Some user account have the username as password: ".join(',',@BadPasswordUsers));
        }else{
            print_report_ok("No user use username as password");
        }
    }else{
        print_report_warn("Unable to check users password, please use a superuser instead");
    }
    my $password_encryption = get_setting('password_encryption');
    if($password_encryption eq 'off'){
        print_report_bad("Password encryption is disabled by default. Password will not be encrypted until explicitely asked");
    }else{
        print_report_ok("Password encryption is enabled");
    }
}

## Connection and memory
## 建议：这里可以添加pg_hba.conf查看里面的trust选项，建议md5
{
    print_header_2("Connection information");
    ### max_connections
    my $max_connections = get_setting("max_connections");
    print_report_info("max_connections: $max_connections");

    ### current connections + ration
    my $current_connections = select_one_value("SELECT count(1) FROM pg_stat_activity");
    my $current_connections_ratio = $current_connections * 100 / $max_connections;
    print_report_info("Current used connections: $current_connections (".format_percent($current_connections_ratio)." of max_connections)");
    if($current_connections_ratio > 70){
        print_report_warn("You are using more than 70% of your max_connections. Increase max_connections before saturation of connection slots");
    }elsif($current_connections_ratio > 90){
        print_report_bad("You are using more than 90% of your max_connections. Increase max_connections before saturation of connection slots");
    }

    ### superuser_reserved_connections
    my $superuser_reserved_connections = get_setting("superuser_reserved_connections");
    my $superuser_reserved_connections_ratio = $superuser_reserved_connections * 100 / $max_connections;
    if($superuser_reserved_connections == 0){
        print_report_bad("No connection reserved for superuser. In case of connection saturation you will not be able to connect to investigate or kill connections");
    }else{
        print_report_info("$superuser_reserved_connections connections reserved for superuser (".format_percent($superuser_reserved_connections_ratio)." of max_connections)");
    }
    if($superuser_reserved_connections_ratio > 20){
        print_report_warn(format_percent($superuser_reserved_connections_ratio) . " of connections are reserved for superuser. This value is too high and can limit other users connections");
    }

    ### average connection age
    my $connection_age_average = select_one_value("SELECT extract(epoch from avg(now() - backend_start)) AS age FROM pg_stat_activity");
    print_report_info("Average connection age: ".format_epoch_to_time($connection_age_average));
    if($connection_age_average < 1 * $min_sec){
        print_report_bad("Average connection age is less than 1 minutes. Use connection pool to manage connections");
    }elsif($connection_age_average < 10 * $min_sec){
        print_report_warn("Average connection age is less than 10 minutes.  Use connection pool to manage these connections");
    }

    ### pre_auth_delay
    my $pre_auth_delay = get_setting("pre_auth_delay");
    $pre_auth_delay =~ s/s//;
    if($pre_auth_delay > 0){
        print_report_bad("pre_auth_delay=$pre_auth_delay: this is a developer feature for debugging and decrease connection delay of $pre_auth_delay seconds");
    }

    ### post_auth_delay
    my $post_auth_delay = get_setting("post_auth_delay");
    $post_auth_delay =~ s/s//;
    if($post_auth_delay > 0){
        print_report_bad("post_auth_delay=$post_auth_delay: this is a developer feature for debugging and decrease connection delay of $post_auth_delay seconds");
    }

    print_header_2("Memory useage");

    ### work_mem
    my $work_mem = get_setting("work_mem");
    print_report_warn("work_mem is per user sort operation, the system will allocate work_mem * total sort operations for all users. So it is highly recommended to modify this at the session level.Like SET work_mem TO \"2MB\"");
    print_report_info("Configured work_mem: ".format_size($work_mem));
    print_report_info("Using an average ratio of work_mem buffers by connections of $work_mem_per_connection_percent% (use --wmp to change it)");
    print_report_info("Total work_mem (per connection): ".format_size($work_mem * $work_mem_per_connection_percent / 100));

    ### shared_buffers
    my $shared_buffers = get_setting("shared_buffers");
    print_report_info("shared_buffers: ".format_size($shared_buffers));
    my $share_buffers_new = format_size(sprintf("%.0d",$os->{mem_total} / 4));
    $share_buffers_new =~ s/\.[\d]*\s//;
    # print "######################" . $share_buffers_new . "##########################\n";
    $db_params{"shared_buffers"} = $share_buffers_new;

    ### wal_buffers
    $db_params{"wal_buffers"} = '-1'; # -1 选择等于shared_buffers的 1/32 的尺寸（大约3%）

    ### track activity
    my $max_processes = $max_connections + get_setting("autovacuum_max_workers");
    if(min_version(9.4)){
        $max_processes += get_setting("max_worker_processes");
        # print "############# $max_processes ##########\n";
    }
    my $track_activity_size = get_setting("track_activity_query_size") * $max_processes;
    # print "############# $track_activity_size ##########\n";
    # print "############# ".get_setting("track_activity_query_size")." ##########\n";
    print_report_info("Track activity reserved size: ".format_size($track_activity_size));

    ### maintenance_work_mem
    my $maintenance_work_mem = get_setting("maintenance_work_mem");
    my $autovacuum_max_workers = get_setting("autovacuum_max_workers");
    if($maintenance_work_mem < 64 * 1024 * 1024){
        print_report_warn("maintenance_work_mem is less than default value. Increase it to reduce maintenance tasks time");
    }else{
        print_report_info("maintenance_work_mem=".format_size($maintenance_work_mem));
    }
    my $maintenance_work_mem_new = format_size(sprintf("%.0d",$os->{mem_total} * 0.25 / $autovacuum_max_workers));
    $maintenance_work_mem_new =~ s/\.[\d]*\s//;
    # print "######################" . $maintenance_work_mem_new . "##########################\n";
    $db_params{"maintenance_work_mem"} = $maintenance_work_mem_new;

    ### total
    # 建议：为get_setting()得到的配置注释参数的用途
    my $maintenance_work_mem_total = $maintenance_work_mem * $autovacuum_max_workers;
    my $work_mem_total = $work_mem * $work_mem_per_connection_percent / 100 * $max_connections;
    my $max_mem = $shared_buffers + $maintenance_work_mem_total + $work_mem_total + $track_activity_size;
    print_report_info("Max memory usage:\n\t\t  shared_buffers (".format_size($shared_buffers).")\n\t\t+ max_connections * work_mem * average_work_mem_buffers_per_connection ($max_connections * ".format_size($work_mem)." * $work_mem_per_connection_percent / 100 = ".format_size($max_connections * $work_mem * $work_mem_per_connection_percent / 100).")\n\t\t+ autovacuum_max_workers * maintenance_work_mem ($autovacuum_max_workers * ".format_size($maintenance_work_mem)." = ".format_size($maintenance_work_mem * $autovacuum_max_workers).")\n\t\t+ track_activity_size (".format_size($track_activity_size).")\n\t\t= ".format_size($max_mem));
    
    ### effective_cache_size
    my $effective_cache_size = get_setting("effective_cache_size");
    print_report_info("effective_cache_size=".format_size($effective_cache_size));
    my $effective_cache_size_new = format_size(sprintf("%.0d",$os->{mem_total} * 0.8));
    $effective_cache_size_new =~ s/\.[\d]*\s//;
    # print "######################" . $effective_cache_size_new . "##########################\n";
    $db_params{"effective_cache_size"} = $effective_cache_size_new;

    ### total database size
    my $all_database_size = select_one_value("SELECT sum(pg_database_size(datname)) FROM pg_database");
    print_report_info("Size of all databases: ".format_size($all_database_size));

    ### shared_buffers usage
    my $shared_buffers_usage = $all_database_size / $shared_buffers;
    if($shared_buffers_usage < 0.7){
        print_report_warn("shared_buffers is too big for the current total database size, memory is lost");
    }

    ### ratio of total RAM
    if(!defined($os->{mem_total})){
        print_report_unknown("OS total memory unknown: unable to analyse PostgreSQL memory usage");
    }else{
        my $percent_postgresql_max_memory = $max_mem * 100 / $os->{mem_total};
        print_report_info("PostgreSQL maximum memory usage: ".format_percent($percent_postgresql_max_memory)." of system RAM");
        if($percent_postgresql_max_memory > 100){
            print_report_bad("Max possibe memory usage for PostgreSQL is more than system total RAM. Add more RAM or reduce PostgreSQL memory");
        }elsif($percent_postgresql_max_memory > 80){
            print_report_warn("Max possible memory usage for PostgreSQL is more than 80% of system total RAM")
        }elsif($percent_postgresql_max_memory < 60){
            print_report_warn("Max possible memory usage for PostgreSQL is less than 60% of system total RAM. On a dedicated hsot you can increase PostgreSQL buffers to optimize performances");
        }else{
            print_report_ok("Max possible memory usage for PostgreSQL is good");
        }

        #### track activity ratio
        my $track_activity_ratio = $track_activity_size * 100 / $os->{mem_total};
        if($track_activity_ratio > 1){
            print_report_warn("Track activity reserved size is more than 1% of system RAM");
            add_advice("track_activity","low","Your track activity reserved size is too high. Reduce track_activity_query_size and/or max_connections");
        }

        #### total ram usage with effective_cache_size
        my $percent_mem_usage = ($max_mem + $effective_cache_size) * 100 / $os->{mem_total};
        print_report_info("max_memory+effective_cache_size is ".format_percent($percent_mem_usage)."% of system RAM");
        if($shared_buffers_usage > 1 and $percent_mem_usage < 60){
            print_report_warn("Increase shared_buffers and/or effective_cache_size to use more memory");
        }elsif($percent_mem_usage > 90){
            print_report_warn("The sum of max_memory and effective_cache_size is too high,the planner can find bad plans if system cacheis smaller than expected");
        }
    }
}

## Table partitioning
{
    print_header_2("Table Partitioning");

    my $constraint_exclusion = get_setting("constraint_exclusion");
    if ( !defined($constraint_exclusion) ) {
        print_report_unknown("parameter constraint_exclusion is unkonwn");
    }else {
        if ( $constraint_exclusion =~ /^partition$/ ) {
            print_report_ok("constraint_exclusion='$constraint_exclusion'");
        }
        elsif ( $constraint_exclusion eq 'off' ) {
            print_report_bad("constraint_exclusion='$constraint_exclusion'. This setting can't help execution plan locating the corresponding partition.");
        }else{
            print_report_warn("constraint_exclusion='$constraint_exclusion'. It will increase the burden of the query optimizer.")
        }
    }

    my @partition_table = select_one_column("SELECT relname FROM pg_class WHERE oid = (SELECT partrelid FROM pg_partitioned_table)");
    if(@partition_table > 0){
        print_report_info("The count of partition tables is " . scalar @partition_table . ", they are :".join(",",@partition_table));
    }else{
        print_report_info("No partiton table");
    }
}

## Huge pages
{
    print_header_2("Huge pages");
    if(min_version('9.4')){
        my $huge_pages = get_setting("huge_pages");
        if($huge_pages eq 'try'){
            print_report_ok("huge_pages = '$huge_pages'");
        }elsif($huge_pages eq 'on'){
            print_report_warn("huge_pages = '$huge_pages'. The database server boot will fail when the allocationg of large pages fails");
        }else{
            print_report_warn("huge_pages = '$huge_pages'. The use of huge pages will improve the performance of smaller page tables and less CPU time spent on memory management.")
        }
    }else{
        print_report_info("Current using version doesn't have 'huge_pages' parameter");
    }
}

## Logs
{
    print_header_2("Logs");

    ### log_hostname
	# 默认情况下，连接日志消息只显示连接主机的 IP 地址。打开这个参数将导致也记录主机名。注意根据你的主机名解析设置，这可能会导致很微小的性能损失。这个参数只能在postgresql.conf文件中或在服务器命令行上设置。 
    my $log_hostname = get_setting("log_hostname");
    if($log_hostname eq 'on'){
        print_report_bad("log_hostname is on: this will decrease connection performance due to reverse DNS lookup"); # DNS反向查询
    }else{
        print_report_ok("log_hostname is off: no reverse DNS lookup latency");
    }

    ### log_min_duration_statement
    my $log_min_duration_statement = get_setting("log_min_duration_statement");
    $log_min_duration_statement =~ s/ms//;
    if($log_min_duration_statement == -1){
        print_report_warn("Log of long queries is deactivated. It will be more difficult to optimize query performance");
    }elsif($log_min_duration_statement < 1000){
        print_report_bad("log_min_duration_statement=$log_min_duration_statement: all queries less than 1 sec will be written in log. It can be disk intense (I/O and space)");
    }else{
        print_report_ok("Long queries will be logged");
    }

    ### log_statement
    my $log_statement = get_setting("log_statement");
    if($log_statement eq 'all'){
        print_report_bad("log_statement=all: this may cause disk intensive and only be useful for debug");
    }elsif($log_statement eq 'mod'){
        print_report_warn("log_statement=mod: this may cause disk intensive");
    }else{
        print_report_ok("log_statement=$log_statement");
    }

    $db_params{"log_destination"} = "'csvlog'";
    $db_params{"logging_collector"} = "on";
    $db_params{"log_truncate_on_rotation"} = "on";
    $db_params{"log_rotation_age"} = "1d";
    $db_params{"log_rotation_size"} = "10MB";
    $db_params{"log_checkpoints"} = 'on';
    $db_params{"log_connections"} = "on";
    $db_params{"log_disconnections"} = "on";
    $db_params{"log_error_verbosity"} = "verbose";
    $db_params{"log_lock_waits"} = "on";
    $db_params{"deadlock_timeout"} = "1s";
    $db_params{"log_statement"} = "'ddl'";
    $db_params{"shared_preload_libraries"} = "'pg_stat_statements'";
    $db_params{"log_line_prefix"} = "'\%t:\%r:\%u@\%d:[\%p]; '"
}

## Two phase commit
{
    print_header_2("Tow phase commit");
    if(min_version('9.2')){
        my $prepared_xact_count = select_one_value("SELECT count(1) FROM pg_prepared_xacts");
        if($prepared_xact_count == 0){
            print_report_ok("Currently no two phase commit transactions");
        }else{
            print_report_warn("There are currently $prepared_xact_count two phase commit prepared transactions. If they are too long they can lock objects");
            my $prepared_xact_lock_count = select_one_value("SELECT count(1) FROM pg_locks WHERE transactionid in (SELECT transaction FROM pg_prepared_xacts)");
            if($prepared_xact_lock_count > 0){
                print_report_bad("Two phase commit transactions have $prepared_xact_lock_count locks!");
            }else{
                print_report_ok("No locks for these $prepared_xact_count transactions");
            }
        }
    }else{
        print_report_warn("The current using version does not supporttwo phase commit");
    }
}

## Autovacuum
{
    print_header_2("Autovacuum");
    if(get_setting("autovacuum") eq 'on'){
        print_report_ok("autovacuum is activited.");
        my $autovacuum_max_workers = get_setting("autovacuum_max_workers");
        print_report_info("autovacuum_max_workers: $autovacuum_max_workers");
    }else{
        print_report_bad("autovacuum is not activited. This is bad except if you known what you do.We strongly recommend setting it to on.");
    }

    $db_params{"vacuum_cost_delay"} = '10ms';
    $db_params{"vacuum_cost_limit"} = '10000';
    $db_params{"autovacuum"} = 'on';
    $db_params{"log_autovacuum_min_duration"} = '0';
}

## Checkpoint
{
    print_header_2("Checkpoint");
    my $checkpoint_completion_target = get_setting("checkpoint_completion_target");
    if($checkpoint_completion_target < 0.5){
        print_report_bad("checkpoint_completion_target($checkpoint_completion_target) is lower than default (0.5)");
        add_advice("checkpoint","urgent","Your checkpoint completion target is too low. Put something nearest from 0.8/0.9 to balance your writesbetter during the checkpoint interval");
    }elsif($checkpoint_completion_target >= 0.5 and $checkpoint_completion_target <= 0.7){
        print_report_warn("checkpoint_completion_target($checkpoint_completion_target) is low");
        add_advice("checkpoint","medium","Your checkpoint completion target is too low. Put something nearest from 0.8/0.9 to balance your writes better during the checkpoint the checkpoint interval");
    }elsif($checkpoint_completion_target > 0.7 and $checkpoint_completion_target <= 0.9){
        print_report_ok("checkpoint_completion_target($checkpoint_completion_target) is OK");
    }elsif($checkpoint_completion_target > 0.9 and $checkpoint_completion_target < 1){
        print_report_warn("checkpoint_completion_target($checkpoint_completion_target) is too near to 1");
        add_advice("checkpoint","medium","Your checkpoint completion target is too high. Put something nearest 0.8/0.9 to balance your writes better during the checkpoint interval");
    }else{
        print_report_bad("checkoint_completion_target too high ($checkpoint_completion_target)");
    }
    $db_params{"checkpoint_completion_target"} = '0.8';

    my $checkpoint_timeout = get_setting("checkpoint_timeout");
    print_report_info("checkpoint_timeout = '$checkpoint_timeout'");
    $db_params{"checkpoint_timeout"} = '5min';
}

## Disk access
{
    print_header_2("Disk access");

    ### fsync wal_sync_method
    my $fsync = get_setting('fsync');
    my $wal_sync_method = get_setting("wal_sync_method"); # 使得整个数据库能够安全写入，也不会降低采用禁用整个磁盘高速缓存方法的应用程序的执行效率
    if($fsync eq 'on'){
        print_report_ok("fsync is on");
    }else{
        print_report_bad("fsync is off. You will loss data in case of crash");
    }
    if($os->{name} eq 'darwin'){
        if($wal_sync_method ne 'fsync_writethrough'){ # Windows和MacOS的特殊值
            print_report_bad("wal_sync_method is $wal_sync_method. Settings other than fsync_writethrough can lead to loss of data in case of crash");
            add_advice("disk access","uergent","set wal_sync_method to fsync_writethrough to on. Otherwise, the disk write cache may prevent recovery after a crash.");
        }else{
            print_report_ok("wal_sync_method is $wal_sync_method");
        }
    }
    if(get_setting("synchronize_seqscans") eq 'on'){
        print_report_ok("synchronize_seqscans is on");
    }else{
        print_report_warn("synchronize_seqscans is off");
        add_advice("seqscan","medium","Set synchronize_seqscans to synchronize seqscans and reduce disks I/O");
    }

    my $full_page_writes = get_setting("full_page_writes");
    if($full_page_writes eq 'on'){
        print_report_ok("full_page_writes = 'on'");
    }else{
        print_report_bad("full_page_writes is off. You will loss data in case of crash")
    }

    ### synchronous_commit
    my $synchronous_commit = get_setting("synchronous_commit");
    if($synchronous_commit eq 'on'){
        print_report_ok("synchronous_commit = 'on'");
    }elsif($synchronous_commit eq 'off'){
        print_report_warn("synchronous_commit = 'off'. This means that there will return success status before WAL write to disk but it will also improve performance");
    }else{
        print_report_info("synchronous_commit = '$synchronous_commit'");
    }
    $db_params{"synchronous_commit"} = 'off';

    $db_params{"bgwriter_delay"} = '10ms';
}

## WAL/PITR
{
    print_header_2("WAL");

    if(min_version('9.0')){
        my $wal_level = get_setting("wal_level");
        if($wal_level eq 'minimal'){
            print_report_bad("This wal_level minimal does not allow PITR backup and recovery");
            add_advice("backup","urgent","Configure your wal_level to a level which allow PITR backup and recovery");
        }
    }else{
        print_report_warn("wal_level is not supported on ".get_setting('server_version'));
    }
}

## Planner
{
    print_header_2("Planner");

    my @ModifiedCosts = select_one_column("SELECT name FROM pg_settings WHERE name like '%cost%' AND setting <> boot_val");
    if(@ModifiedCosts > 0){
        print_report_warn("Some cost settings are not the defaults: ".join('.',@ModifiedCosts).". This can have bad impacts on performance. Use at your own risk");
    }else{
        print_report_ok("Cost settings are defults");
    }

    ### random vs seq page cost on SSD
    my $random_page_cost = get_setting("random_page_cost");
    # print "########################   $random_page_cost  ##############################\n";
    my $seq_page_cost = get_setting("seq_page_cost");
    # print "########################   $seq_page_cost  ##############################\n";
    # if(!defined($HDD)){
    if(@HDD == 0 && @SSD == 0){
        print_report_unknown("Information about rotational/SSD disk is unknown: unable to check random_page_cost and seq_page_cost tuning");
    }else{
        if(@HDD == 0 and $random_page_cost > $seq_page_cost){
            print_report_warn("With SSD storage,set random_page_cost=seq_page_cost to help planner use more index scan");
            add_advice("planner","medium","Set random_page_cost=seq_page_cost on SSD disks");
        }elsif(@HDD > 0 and $random_page_cost <= $seq_page_cost){
            print_report_bad("Without SSD storage, random_page_cost must br more than seq_page_cost");
            add_advice("planner","urgent","Set random_page_cost to 2-4 times more than seq_page_cost without SSD storage");
        }
    }

    ### disabled plan functions
    my @DisabledPlanFunctions = select_one_column("SELECT name,setting from pg_settings WHERE name LIKE 'enable_%' AND setting='off'");
    if(@DisabledPlanFunctions > 0){
        print_report_bad("Some plan features are disabled: ".join(',',@DisabledPlanFunctions));
    }else{
        print_report_ok("All plan features are enabled");
    }
}

# Database information
print_header_1("Database information for database $database");

## Database tables size
{
    print_header_2("Database size");
    my $sum_total_relation_size = select_one_value("SELECT sum(pg_total_relation_size(schemaname||'.'||tablename)) FROM pg_tables"); # quote_ident(tablename) # 指定表所用的总磁盘空间，包括所有的索引和TOAST数据 
    print_report_info("Database $database total size: ".format_size($sum_total_relation_size));
    if(min_version('9.0')){
        my $sum_table_size = select_one_value("SELECT sum(pg_table_size(schemaname||'.'||tablename)) FROM pg_tables"); # 被指定表使用的磁盘空间，排除索引（但包括 TOAST、空闲空间映射和可见性映射）
        my $sum_index_size = $sum_total_relation_size - $sum_table_size;
        # print_report_debug("sum_total_relation_size: $sum_total_relation_size");
        # print_report_debug("sum_table_size: $sum_table_size");
        # print_report_debug("sum_index_size: $sum_index_size");
        # my $table_percent = $sum_table_size * 100 / $sum_total_relation_size;
        # my $index_percent = $sum_index_size * 100 / $sum_total_relation_size;
        print_report_info("Database $database tables size: ".format_percent($sum_table_size));
        print_report_info("Database $database indexes size: ".format_percent($sum_index_size));
    }
}

# Tablespace location
{
    print_header_2("Tablespace location");
    if(min_version('9.2')){
        my $tablespaces_in_pgdata = select_all_hashref("SELECT spcname,pg_tablespace_location(oid) from pg_tablespace WHERE pg_tablespace_location(oid) LIKE (SELECT setting FROM pg_settings WHERE name='data_directory')||'/%'",'spcname');
        if(keys(%{$tablespaces_in_pgdata}) == 0){
            print_report_ok("No tablespace in \$PGDATA");
        }else{
            print_report_bad("Some tablespaces are in \$PGDATA ".join(' ',keys(%{$tablespaces_in_pgdata})));
            add_advice("tablespaces","urgent","Some tablespaces are in \$PGDATA. Move them outside of this folder.");
        }
    }else{
        print_report_unknown("This check is not supported before 9.2");
    }
}

## Shared buffers usage
# 建议：可以扩展
{
    print_header_2("Shared buffer hit rate");
    
    ### Heap hit rate
    {
        my $shared_buffer_heap_hit_rate = select_one_value("SELECT sum(heap_blks_hit)*100/(sum(heap_blks_read)+sum(heap_blks_hit)+1) FROM pg_statio_all_tables");
        print_report_info("shared_buffer_heap_hit_rate: ".format_percent($shared_buffer_heap_hit_rate));
    }

    ## TOAST hit rate
    {
        my $shared_buffer_toast_hit_rate = select_one_value("SELECT sum(toast_blks_hit)*100/(sum(toast_blks_read)+sum(toast_blks_hit)+1) FROM pg_statio_all_tables");
        print_report_info("shared_buffer_toast_hit_rate: ".format_percent($shared_buffer_toast_hit_rate));
    }

    ## Tidx hit rate(TOAST table index)
    {
        my $shared_buffer_tidx_hit_rate = select_one_value("SELECT sum(tidx_blks_hit)*100/(sum(tidx_blks_read)+sum(tidx_blks_hit)+1) FROM pg_statio_all_tables");
        print_report_info("shared_buffer_tidx_hit_rate: ".format_percent($shared_buffer_tidx_hit_rate));
    }

    ## Idx hit rate
    {
        my $shared_buffer_idx_hit_rate = select_one_value("SELECT sum(idx_blks_hit)*100/(sum(idx_blks_read)+sum(idx_blks_hit)+1) FROM pg_statio_all_tables");
        print_report_info("Shared_buffer_idx_hit_rate: ".format_percent($shared_buffer_idx_hit_rate));
        if($shared_buffer_idx_hit_rate > 99.99){
            print_report_info("Shared_buffer_idx_hit_rate is too high. You can reduce shared_buffers if you needed");
        }elsif($shared_buffer_idx_hit_rate > 98){
            print_report_ok("Shared_buffer_idx_hit_rate is good");
        }elsif($shared_buffer_idx_hit_rate > 90){
            print_report_warn("Shared_buffer_idx_hit_rate is quite good. Increase shared_buffer memory to increase hit rate");
        }else{
            print_report_bad("Shared_buffer_idx_hit_rate is too low. Increase shared_buffers memory to increase hit rate");
        }
    }
}

## Indexes
{
    print_header_2("Indexes");

    # Invalid indexes
    {
        my @Invalid_indexes = select_one_column("SELECT relname FROM pg_index JOIN pg_class ON indexrelid=oid WHERE indisvalid=false");
        if(@Invalid_indexes > 0){
            print_report_bad("There are invalid indexes in the database $database.");
            add_advice("index","urgent","You have invalid indexes in the database. Please check/rebuild them");
        }else{
            print_report_ok("No invalid indexes");
        }
    }

    ## Unused indexes
    {
        my @Unused_indexes;
        if(min_version('9.0')){
            @Unused_indexes = select_one_column("SELECT relname||'.'||indexrelname FROM pg_stat_user_indexes WHERE idx_scan=0 AND not exists (SELECT 1 FROM pg_constraint WHERE conindid=indexrelid) ORDER BY relname,indexrelname");
        }else{
            @Unused_indexes = select_one_column("SELECT relname||'.'||indexrelname FROM pg_stat_user_indexes WHERE idx_scan=0 ORDER BY relname,indexrelname");
        }
        if(@Unused_indexes > 0){
            print_report_warn("Some indexes are unused since the last statistics run: @Unused_indexes");
            add_advice("index","medium","You have unused indexes in the database sine the last statistics run. Please remove them if they are not used");
        }else{
            print_report_ok("No unused indexes");
        }
    }

    ## Index expansion
    {
        my @index_ratio = select_one_column("SELECT index_ratio FROM(SELECT nspname,relname,round(100* pg_relation_size(indexrelid) / pg_relation_size(indrelid))/100 AS index_ratio,pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,pg_size_pretty(pg_relation_size(indrelid)) AS table_size FROM pg_index I LEFT JOIN pg_class C ON(C.oid = I.indexrelid) LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace) WHERE nspname NOT IN('pg_catalog','information_schema','pg_toast') AND C.relkind='i' AND pg_relation_size(indrelid)>0) AS foo WHERE index_ratio > 1");
        if(@index_ratio > 0){
                foreach(@index_ratio){
                if($_ > 1){
                    my $relname_ref = select_all_hashref("SELECT nspname,relname,round(100* pg_relation_size(indexrelid) / pg_relation_size(indrelid))/100 AS index_ratio,pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,pg_size_pretty(pg_relation_size(indrelid)) AS table_size FROM pg_index I LEFT JOIN pg_class C ON(C.oid = I.indexrelid) LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace) WHERE nspname NOT IN('pg_catalog','information_schema','pg_toast') AND C.relkind='i' AND pg_relation_size(indrelid)>0","index_ratio");
                    my $relname = $relname_ref->{$_}->{relname};
                    my $nspname = $relname_ref->{$_}->{nspname};
                    print_report_warn("$nspname.$relname may have index expansion. You can execute reindex or vacuum");
                }
            }
        }else{
            print_report_ok("No index expansion");
        }
    }
}

## Procedures
{
    print_header_2("Procedures");
    # Procedures with default cost
    {
        my @Default_cost_procs = select_one_column("SELECT n.nspname||'.'||p.proname FROM pg_catalog.pg_proc p LEFT JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE pg_catalog.pg_function_is_visible(p.oid) AND n.nspname NOT IN ('pg_catalog','information_schema','sys') AND p.prorows <> 1000 AND p.proname NOT LIKE 'uuid_%' AND p.proname != 'pg_stat_statements_reset'");
        if(@Default_cost_procs > 0){
            print_report_warn("Some user procedures do not have custom cost and rows settings: @Default_cost_procs");
            add_advice("proc","low","You have custom procedures with default cost and rows setting. Please reconfigure them with specific values to help the planner");
        }else{
            print_report_ok("No procedures with default costs");
        }
    }
}

print_advices();

sub print_advices {
    print "\n";
    print_header_1("Configuration advice");

    my $advice_count = 0;
    foreach my $category (sort(keys(%advices))){
        print_header_2("$category");
        foreach my $priority (sort(keys(%{$advices{$category}}))){
            print color('red') if $priority eq 'urgent';
            print color('yellow') if $priority eq 'medium';
            print color('magenta') if $priority eq 'low';
            foreach my $advice (@{$advices{$category}{$priority}}){
                print "[".uc($priority)."] $advice\n";
                $advice_count++;
            }
            print color('reset');
        }
    }
    if($advice_count == 0){
        print color('green')."Everything is good".color('reset')."\n";
    }
}

sub format_percent {
    my $value = shift;
    return sprintf("%.2f%%",$value);
}

print color("red") . "\nDo you want to know current db tps?(Y/N)" . color("reset");
chomp(my $global_flag = <STDIN>);
if($global_flag =~ /^Y$/i){
    $TPS{"original"} = getTPS();
    print "Current TPS is : $TPS{'original'}\n";
}

# Linux kernel parameter tuning
{
    print_header_1("Linux Kernel Parameters");

    my $config_file = get_setting("config_file");
    $config_file =~ /([\w\W]+\/)postgresql\.conf$/;
    my $pid = `head -1 $1/postmaster.pid`;chomp($pid);
    my $peak = `grep ^VmPeak /proc/$pid/status | awk '{ print \$2 }'`;chomp($peak);
    my $hps = `grep ^Hugepagesize /proc/meminfo | awk '{ print \$2 }'`;chomp($hps);
    my $hp = sprintf("%d",$peak / $hps);

    my %params_values = (
        'vm.zone_reclaim_mode' => '0',
        'kernel.numa_balancing' => '0',
        'vm.nr_hugepages' => $hp,
        'vm.swappiness' => '1',
        'vm.dirty_ratio' => '95',
        'vm.dirty_background_ratio' => '5',
        'vm.dirty_background_bytes' => '409600000',
        'vm.dirty_bytes' => '0',
        'kernel.sched_migration_cost_ns' => '500000',
        'kernel.sched_autogroup_enabled' => '0',
        'kernel.shmmax' => '18446744073692774399',
        'kernel.shmall' => '18446744073692774399',
        'vm.overcommit_memory' => '2',
        'fs.aio-max-nr' => '1048576',
        'net.core.wmem_default' => '262144',
        'fs.file-max' => '76724600',
        'vm.mmap_min_addr' => '65536',
        'net.core.somaxconn' => '4096',
        'net.core.wmem_max' => '4194304',
        'net.core.netdev_max_backlog' => '10000',
        'kernel.sem' => '4096 2147483647 2147483646 512000',
        'net.core.rmem_max' => '4194304',
        'vm.overcommit_ratio' => '90',
        'net.ipv4.tcp_tw_reuse' => '1',
        'net.core.rmem_default' => '262144',
        'net.ipv4.ip_local_port_range' => '40000 65535',
        # 'net.netfilter.nf_conntrack_max' => '1200000',
        'net.ipv4.tcp_rmem' => '8192 87380 16777216',
        'net.ipv4.tcp_max_syn_backlog' => '4096',
        'fs.nr_open' => '20480000',
        'net.ipv4.tcp_wmem' => '8192 87380 16777216',
        'vm.dirty_writeback_centisecs' => '100',
        'kernel.shmmni' => '819200',
        'net.ipv4.tcp_mem' => '8388608 12582912 16777216',
        # 'net.nf_conntrack_max' => '1200000',
        'net.ipv4.tcp_max_tw_buckets' => '262144',
    );

    print color('bold red')."Would you like to tune OS kernel parameters?(Y/N)".color('reset');
    chomp(my $flag = <STDIN>);

    if ( $flag =~ /^Y$/i ) {
        if ( $os->{name} eq 'linux' ) {
            if ( !( -e "tuning_kernel.out" ) ) {
                system "touch tuning_kernel.out";
                open my $sys_fh, ">>", "tuning_kernel.out"
                or die
                "Can't write sysctl default values to 'tuning_kernel.out':$!";
                foreach ( keys %params_values ) {
                    # print "$_ = $params_values{$_}\n";
                    print $sys_fh $_ . " = " . os_cmd_kernel("sysctl $_") . "\n";
                }
                close $sys_fh;
            }

            print color('bold red')."The followed params will be set with these values:\n".color('reset');
            foreach(keys %params_values){
                print "$_ = $params_values{$_}\n";
            }

            print color('bold red')."Do you want to set params by yourself?(Y/N)".color('reset');
            chomp($flag = <STDIN>);
            if($flag =~ /^Y$/i){
                while(1){
                    print "Enter new values(params=value, 'q' to quit): ";
                    chomp($flag = <STDIN>);
                    if($flag =~ /^q$/){
                        last;
                    }elsif($flag =~ /([\d\D]+)=([\d\D]+)/){
                        $params_values{$1} = $2;
                    }else{}
                }
                # foreach(keys %params_values){
                #     os_cmd("echo \"$_=$params_values{$_}\" >> /etc/sysctl.conf");
                # }
            }else{
                # foreach(keys %params_values){
                #     os_cmd("echo \"$_=$params_values{$_}\" >> /etc/sysctl.conf");
                # }
            }

            foreach(keys %params_values){
                os_cmd("echo \"$_=$params_values{$_}\" >> /etc/sysctl.conf");
            }
            
            os_cmd("echo \"postgres soft  core unlimited\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres hard  nproc unlimited\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres soft  nproc unlimited\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres hard  memlock unlimited\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres hard  nofile 1024000\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres soft  memlock unlimited\" >> /etc/security/limits.conf");
            os_cmd("echo \"postgres soft  nofile 1024000\" >> /etc/security/limits.conf");
            print_report_info("Kernel parameters setting completed. The default values have been print into 'tuning_kernel.out' in current directory");

            print color("red") . "Do you want to know current db tps?(Y/N)" . color("reset");
            chomp($global_flag = <STDIN>);
            if($global_flag =~ /^Y$/i){
                $TPS{"kernel"} = getTPS();
                print "Current TPS is : $TPS{'kernel'}\n";
            }
            if($TPS{'original'}){
                printf ("Performance compare to default settings has improved :%d %\n",($TPS{'kernel'} - $TPS{'original'}) * 100 / $TPS{'original'});
            }
        }else {
            print_report_warn("Sorry, this script doesn't support tuning current OS' kernel parameters");
        }
    }else {
        print_report_info("Nothing changed");
    }
}

sub os_cmd_kernel {
    my $command = $os_cmd_prefix.shift;
    local $SIG{__WARN__} = sub {};
    my $result = `$command 2>&1`; 
    if( $? == 0){ 
        chomp($result);
        if($result =~ /[\d\D]+=\s([\d\D]+)/){
            return $1;
        }
    }else{
        warn("Command $command failed");
        return undef;
    }
}

# postgresql.conf
{
    print_header_1("Postgresql Configuration");

    print color('bold red')."Would you like to modify postgresql.conf parameters?(Y/N)".color('reset');

    chomp(my $flag = <STDIN>);
    if ( $flag =~ /^Y$/i ) {
        my $config_file = get_setting("config_file");
        unless(-e "postgresql.conf.bak"){
            system "cp $config_file postgresql.conf.bak";
        }
        open my $config_fh, ">>", $config_file
        or die
        "Can't write values into '$config_file':$!";
        foreach ( keys %db_params ) {
            # print "$_ = $db_params{$_}\n";
            print $config_fh "$_ = $db_params{$_}\n";
        }
        close $config_fh;
        print_report_info("Configurations setting completted. The original configuration file has been backed up to the current directory");

        print color("red") . "\nDo you want to know current db tps?(Y/N)" . color("reset");
        chomp($global_flag = <STDIN>);
        if($global_flag =~ /^Y$/i){
            # system "su - postgres -c '$1/bin/pg_ctl restart -D $1/data'";
            # if($config_file =~ /([\d\D]+)\/bin.*/){
                $dbh->disconnect();
                # system `$1/bin/pg_ctl restart -D $1/data`;
                # system "su - postgres -c '$1/bin/pg_ctl reload -D $1/data'";
                # my $restart = "su - postgres -c '$1/bin/pg_ctl restart -D $1/data'";
                system "su - postgres -c 'pg_ctl restart'";
                sleep(5);
                $dbh = DBI->connect("dbi:Pg:dbname=$database;host=$host;port=$port;",$username,$password,{AutoCommit=>1,RaiseError=>1,PrintError=>0});
            # }
            # my $cdh = $dbh->prepare("SELECT pg_reload_conf()");
            # my $tmp = $cdh->execute();
            # print_report_warn("Only part params being effective,you better restart database");
            $TPS{"config"} = getTPS();
            print "Current TPS is : $TPS{'config'}\n";
            if($TPS{'original'}){
                printf ("Performance compare to default settings has improved :%d %\n",($TPS{'config'} - $TPS{'original'}) * 100 / $TPS{'original'});
            }
            # system "logout";
        }
    }else {
        my $config_file = get_setting("config_file");
        system "cp $config_file postgresql.conf.new";
        open my $config_fh, ">>", "postgresql.conf.new"
        or die
        "Can't write values into 'postgresql.conf.new':$!";
        foreach ( keys %db_params ) {
            # print "$_ = $db_params{$_}\n";
            print $config_fh "$_ = $db_params{$_}\n";
        }
        close $config_fh;
        print_report_info("Nothing changed. New config file has been stored in current directory");
    }
}

# Explain sql
# {
#     print_header_1("Explain SQL");
#     print "If you want to explain SQL statements, enter it in a line('exit' to exit)";
#     chomp(my $flag = <STDIN>);
#     print "\n";
#     while(defined($flag) and $flag ne 'exit'){
#         my @explain = select_one_column("EXPLAIN ANALYZE " . $flag);
#         foreach(@explain){
#             print $_."\n";
#         }
#         print "If you want to explain SQL statements, enter it in a line('exit' to exit)";
#         chomp($flag = <STDIN>);
#         print "\n";
#     }
# }

sub getTPS {
    # print "############################################\n";
    chomp(my $logic_cores = `cat /proc/cpuinfo| grep "processor"| wc -l`);
    $logic_cores *= 4;
    # print $logic_cores;
    my $TPS = 0;
    
    my $cdb = $dbh->prepare("DROP DATABASE IF EXISTS pgbench");
    $cdb->execute();
    $cdb = $dbh->prepare("CREATE DATABASE pgbench");
    $cdb->execute();

    # my $config_file = get_setting("config_file");
    # print "$config_file\n";
    # if($config_file =~ /([\d\D]+)\/\..*/){
        my $init_db = `su - postgres -c 'pgbench -i pgbench -U postgres 2>&1'`;
        print "Please wait 1min...\n";
        my $result = `su - postgres -c 'pgbench -U postgres -c $logic_cores -T 10 pgbench'`;
        if($result =~ /estab[\d\D]+tps\s=\s([\d\D]+)\s\(ex/){
            # print "$1\n";
            $TPS = $1;
        }
        # print $result;
    # }
    return $TPS;
}

$dbh->disconnect();

exit(0);