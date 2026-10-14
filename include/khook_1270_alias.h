#ifndef KHOOK_1270_ALIAS_H
#define KHOOK_1270_ALIAS_H

/* Build the tested 12.70 hook alongside the original 13.x hook.  The
 * different arm and continuation chains are selected at compile time. */
#define kh_chain_init       kh1270_chain_init
#define kh_chain_q          kh1270_chain_q
#define kh_chain_g          kh1270_chain_g
#define kh_chain_store      kh1270_chain_store
#define kh_chain_memcpy     kh1270_chain_memcpy
#define kh_chain_call       kh1270_chain_call
#define kh_init             kh1270_init
#define kh_set_hook_target  kh1270_set_hook_target
#define kh_set_resume_rip   kh1270_set_resume_rip
#define kh_set_resume_skip  kh1270_set_resume_skip
#define kh_set_resume_rax   kh1270_set_resume_rax
#define kh_clear_resume_rax kh1270_clear_resume_rax
#define kh_set_resume_rsi   kh1270_set_resume_rsi
#define kh_clear_resume_rsi kh1270_clear_resume_rsi
#define kh_set_resume_rdi   kh1270_set_resume_rdi
#define kh_clear_resume_rdi kh1270_clear_resume_rdi
#define kh_set_resume_rdx   kh1270_set_resume_rdx
#define kh_clear_resume_rdx kh1270_clear_resume_rdx
#define kh_set_tables      kh1270_set_tables
#define kh_set_core        kh1270_set_core
#define kh_find_cave       kh1270_find_cave
#define kh_user_data_addr  kh1270_user_data_addr
#define kh_install         kh1270_install
#define kh_trigger         kh1270_trigger
#define kh_disarm          kh1270_disarm
#define kh_restore         kh1270_restore

#endif
