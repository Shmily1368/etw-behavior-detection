#include "stdafx.h"
#include "setting.h"
#include "tool_functions.h"

void Setting::Init(int argc, char* argv[])
{
	try
	{
		options_description opts("DataCollector Allowed Options");
		//所有配置都需要加入opts中，以此来有效控制配置;
		opts.add_options()
			("help", value<string>(), "just a help info")
			("mode", value<char>(), "n: offline log file , p: offline parse mode, f: online parse mode;eg: --mode=f")
			("kafka_data_tunnel_topic", value<string>(), "collector->detectoc kafka topic name")

			//setting in user_configuration.txt,need to be defined here;fix chips;

			("kafka_address", value<string>(), "kafka ip:port")
			("kafka_partition", value<int>(), "kafka partition in this topic")	

			("win7_format_file", value<string>(), "define event struct in win7")
			("win10_format_file", value<string>(), "define event struct in win10")

			("output", value<string>(), "output switch, you can choose: 1.Kafka(kafka output) 2.Json(local output) 3.None(no output), if you want multiple output, you can use | for segment; eg: output=Kafka|Json")
			("optimize_api_parse", value<bool>(), "you can choose: 1.true(use optimize api parse) 2.false(use runqing api parse)")
			("local_detector_parse", value<bool>(), "you can choose: 1.true(output phf) 2.false(output api)")
			("local_detector_mode", value<String>(), "you can choose: 1.callstack 2.syscall")
			("get_visiblewindow_task_interval", value<int>(), "interval time to get visiblewindow")

			//offline mode
			("offline_log_file", value<string>(), "binary file path which will be parsed in offline parse")
			("offline_dll_rva_folder_path", value<string>(), "rva dir path which will be parsed in offline parse")
			("offline_drive_map_file", value<string>(), "map about key is drive format and value is device format in offline parse")
			("offline_output_whitelist_processid", value<string>(), "1.only parse output_whitelist_processid in offline normal filter mode;2.only parse output_whitelist_processid in offline father&child filter mode")
			("offline_process_filter_mode", value<string>(), "choose parse range, you can choose: 1.normal(particular process) 2.father&child(particular process and sub process) 3.all")
			("enable_maximum_dump", value<bool>(), "whether create maximum dump when crash")
			("enable_performance_monitor", value<bool>(), "whether monitor system performance")
			("init_gear", value<int_32>(), "collector init gear")
			("enable_gear_adjustment", value<bool>(), "whether enable gear adjustment")
			("enable_hardware_adjustment", value<bool>(), "whether enable hardware adjustment")
			("autorun_info_file_simplified", value<String>(), "simplified autorun info file name for client scheduler")
			("autorun_info_file_full", value<String>(), "full autorun info file name for client scheduler")
			("enable_ransom_detector", value<bool>(), "you can choose: 1.true(enable_ransom_detector) 2.false(disable_ransom_detector)")
			("enable_ransom_terminate", value<bool>(), "you can choose: 1.true(enable_ransom_terminate) 2.false(disable_ransom_terminate)")
			("ransom_detector_collect", value<bool>(), "防勒索采集模式，true开启，即不进行归一化和模型预测，false，关闭，默认值")
            ("enable_ransom_output", value<bool>(), "you can choose: 1.true(enable_ransom_output) 2.false(disable_ransom_output)")
            ("enable_honey_pot", value<bool>(), "you can choose: 1.true(enable_honey_pot) 2.false(disable_honey_pot)")  
            ("enable_debug_output", value<bool>(), "you can choose: 1.true(enable_debug_output) 2.false(disable_debug_output)") 
			("enable_pruner_output", value<bool>(), "you can choose: 1.true(enable_pruner_output) 2.false(disable_pruner_output)")
            ("kafka_user_name", value<String>(), "set kafka authorization user name")
            ("kafka_password", value<String>(), "set kafka authorization password")
            ("enable_rule_match", value<bool>(), "you can choose: 1.true(enable_rule_match) 2.false(disable_rule_match)")
            ("enable_powershell_detector", value<bool>(), "you can choose: 1.true(enable_powershell_detector) 2.false(disable_powershell_detector)")
			("enable_process_whitelist", value<bool>(), "you can choose: 1.true(enable_process_whitelist) 2.false(disable_process_whitelist)")
			("ransom_feature_remove_duplicates", value<int>(), "防勒索检查去重窗口设置，0-不去重，>0则去重后设定次数个特征检查")
			;

		variables_map config_map;
		store(parse_command_line(argc, argv, opts), config_map); //解析命令行参数;
		store(parse_config_file<char>(CONFIG_FILE_NAME.c_str(), opts, true), config_map);//解析文件中的参数,true时允许配置文件中出现未定义的选项;

		if (config_map.count("help"))
		{
#ifdef OUTPUT_COMMAND_LINE
			cout << opts << endl;
#endif // OUTPUT_COMMAND_LINE;	
			system("pause");

			exit(1);
		}

		m_collector_mode = config_map["mode"].as<char>();
		m_verification = EMPTY_STRING;//_config_map["temp"].as<String>();
		m_kafka_address = config_map["kafka_address"].as<String>();
		m_kafka_topic = config_map["kafka_data_tunnel_topic"].as<String>();
		m_kafka_partition = config_map["kafka_partition"].as<int_32>();
		m_format_file = ToolFunctions::GetSystemOs() == EM_OsVersion::WIN7 ? config_map["win7_format_file"].as<String>() : config_map["win10_format_file"].as<String>();
		m_output_mode = config_map["output"].as<String>();
		m_optimize_api_parse = config_map["optimize_api_parse"].as<bool>();
		m_local_detector_parse = config_map["local_detector_parse"].as<bool>();
		m_local_detector_mode = config_map["local_detector_mode"].as<String>();
		m_visible_window_task_interval = config_map["get_visiblewindow_task_interval"].as<int_32>();
		m_offline_log_file = config_map["offline_log_file"].as<String>();
		m_offline_dll_rva_folder = config_map["offline_dll_rva_folder_path"].as<String>();
		m_offline_drive_map_file = config_map["offline_drive_map_file"].as<String>();
		m_offline_process_filter_mode = config_map["offline_process_filter_mode"].as<String>();
		m_offline_output_whitelist_process_id = config_map["offline_output_whitelist_processid"].as<String>();
		m_enable_maximum_dump = config_map["enable_maximum_dump"].as<bool>();
		m_enable_performace_monitor = config_map["enable_performance_monitor"].as<bool>();
		m_collector_init_gear = config_map["init_gear"].as<int_32>();
		m_enable_gear_adjustment = config_map["enable_gear_adjustment"].as<bool>();
		m_enable_hardware_adjustment = config_map["enable_hardware_adjustment"].as<bool>();
		m_autorun_info_file_simplified = config_map["autorun_info_file_simplified"].as<String>();
		m_autorun_info_file_full = config_map["autorun_info_file_full"].as<String>();
		m_enable_ransom_detector = false;
		m_enable_ransom_terminate = false;
		m_enable_ransom_output = false;
		m_ransom_detector_collect = false;
		m_ransom_feature_remove_duplicates = 0; 
		/*
        if (config_map.count("enable_ransom_detector")) 
            m_enable_ransom_detector = config_map["enable_ransom_detector"].as<bool>();

		if (m_enable_ransom_detector)
		{
			if (config_map.count("enable_ransom_terminate")) 
				m_enable_ransom_terminate = config_map["enable_ransom_terminate"].as<bool>();
			if (config_map.count("enable_ransom_output")) 
				m_enable_ransom_output = config_map["enable_ransom_output"].as<bool>();
			if (config_map.count("ransom_detector_collect"))
				m_ransom_detector_collect = config_map["ransom_detector_collect"].as<bool>();
			if (config_map.count("ransom_feature_remove_duplicates"))
				m_ransom_feature_remove_duplicates = config_map["ransom_feature_remove_duplicates"].as<int>();
		}
		*/
        m_enable_honey_pot = false;
        
        if (config_map.count("enable_debug_output")) {
            m_enable_debug_output = config_map["enable_debug_output"].as<bool>();
        }
        else {
            m_enable_debug_output = false;
            WriteLog4cPlus(WARN_LEVEL, L"setting init no enable_debug_output, set default false");
        }
		// set enable_pruner_output
        if (config_map.count("enable_pruner_output")) {
            m_enable_pruner_output = config_map["enable_pruner_output"].as<bool>();
        }
        else {
            m_enable_pruner_output = false;
            WriteLog4cPlus(WARN_LEVEL, L"setting init no enable_pruner_output, set default false");
        }
        // add by zxw on 20200909
        // set kafka_user_name
        if (config_map.count("kafka_user_name")) {
            m_kafka_user_name = config_map["kafka_user_name"].as<String>();
        }
        else {
            m_kafka_user_name = "";
            /* Credential values intentionally excluded from logging. */
        }
        // set kafka_password
        if (config_map.count("kafka_password")) {
            m_kafka_password = config_map["kafka_password"].as<String>();
        }
        else {
            m_kafka_password = "";
            /* Credential values intentionally excluded from logging. */
        }

        m_enable_rule_match = false;

		if (config_map.count("enable_process_whitelist")) {
			m_enable_process_whitelist = config_map["enable_process_whitelist"].as<bool>();
		}
		else {
			m_enable_process_whitelist = true;
			WriteLog4cPlus(WARN_LEVEL, L"setting init no enable_process_whitelist, set default true");
		}
        m_enable_powershell_detector = false;	

		/* Credential values intentionally excluded from logging. */
	}
	catch (...)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"setting init error, may exist config param not be allowed or style is error, please start with --help for help");
		exit(1);
	}
}
