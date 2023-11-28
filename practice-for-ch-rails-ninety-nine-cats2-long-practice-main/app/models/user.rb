# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  username        :string           not null
#  email           :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    before_validation :ensure_session_token
    #FIGVAPEBR
    attr_reader :password

    def self.find_by_credentials(username, password) 
        @user = User.find_by(username: username)
            if @user && @user.is_password?(password)
                @user 
            else 
                nil 
            end
    end

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        pass_obj = BCrypt::Password.new(self.password_digest)
        pass_obj.is_password?(password)
    end

    def ensure_session_token
        self.session_token ||= SecureRandom::urlsafe_base64
    end

    def reset_session_token!
        self.session_token = SecureRandom::urlsafe_base64
        while !self.save
            self.session_token = SecureRandom::urlsafe_base64
        end
        self.session_token
        # self.save! will return a "loud" error
    end

    validates :username, :session_token, :email, presence: true, uniqueness: true
    validates :password, presence: true, length: { minimum: 6 }
    validates :password_digest, presence: true
    
end
